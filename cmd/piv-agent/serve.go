package main

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-systemd/activation"
	"github.com/smlx/piv-agent/internal/pivservice"
	"github.com/smlx/piv-agent/internal/server"
	"github.com/smlx/piv-agent/internal/ssh"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type agentTypeFlag map[string]uint

// ServeCmd represents the listen command.
type ServeCmd struct {
	LoadKeyfile bool          `kong:"default=true,help='Load the key file from ~/.ssh/id_ed25519'"`
	ExitTimeout time.Duration `kong:"default=32m,help='Exit after this period to drop transaction and key file passphrase cache'"`
	AgentTypes  agentTypeFlag `kong:"default='ssh=0;gpg=1',help='Agent types to handle'"`
}

// validAgents is the list of agents supported by piv-agent.
var validAgents = []string{"ssh", "gpg"}

// AfterApply validates the given agent types.
func (flagAgents *agentTypeFlag) AfterApply() error {
	for flagAgent := range map[string]uint(*flagAgents) {
		valid := false
		for _, validAgent := range validAgents {
			if flagAgent == validAgent {
				valid = true
			}
		}
		if !valid {
			return fmt.Errorf("invalid agent-type: %v", flagAgent)
		}
	}
	return nil
}

// Run the listen command to start listening for ssh-agent requests.
func (cmd *ServeCmd) Run(log *zap.Logger) error {
	log.Info("startup", zap.String("version", version),
		zap.String("build date", date))
	p := pivservice.New(log)
	// use systemd socket activation
	ls, err := activation.Listeners()
	if err != nil {
		return fmt.Errorf("cannot retrieve listeners: %w", err)
	}
	// validate given agent types
	if len(ls) != len(cmd.AgentTypes) {
		return fmt.Errorf("wrong number of agent sockets: wanted %v, received %v",
			len(cmd.AgentTypes), len(ls))
	}
	// prepare dependencies
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exit := time.NewTicker(cmd.ExitTimeout)
	g := errgroup.Group{}
	// start SSH agent if given in agent-type flag
	if _, ok := cmd.AgentTypes["ssh"]; ok {
		log.Debug("starting SSH server")
		g.Go(func() error {
			s := server.NewSSH(log)
			a := ssh.NewAgent(p, log, cmd.LoadKeyfile)
			err := s.Serve(ctx, a, ls[cmd.AgentTypes["ssh"]], exit, cmd.ExitTimeout)
			cancel()
			return err
		})
	}
	if _, ok := cmd.AgentTypes["gpg"]; ok {
		log.Debug("starting GPG server")
		g.Go(func() error {
			s := server.NewGPG(p, log)
			err := s.Serve(ctx, ls[cmd.AgentTypes["gpg"]], exit, cmd.ExitTimeout)
			cancel()
			return err
		})
	}
loop:
	for {
		select {
		case <-ctx.Done():
			log.Debug("exit done")
			break loop
		case <-exit.C:
			log.Debug("exit timeout")
			cancel()
			break loop
		}
	}
	return g.Wait()
}
