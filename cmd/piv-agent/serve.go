package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/smlx/piv-agent/internal/keyservice/piv"
	"github.com/smlx/piv-agent/internal/pinentry"
	"github.com/smlx/piv-agent/internal/server"
	"github.com/smlx/piv-agent/internal/sockets"
	"github.com/smlx/piv-agent/internal/ssh"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type agentTypeFlag map[string]uint

// ServeCmd represents the listen command.
type ServeCmd struct {
	LoadKeyfile bool          `kong:"default=true,help='Load the key file from ~/.ssh/id_ed25519'"`
	ExitTimeout time.Duration `kong:"default=12h,help='Exit after this period to drop transaction and key file passphrase cache, even if service is in use'"`
	IdleTimeout time.Duration `kong:"default=32m,help='Exit after this period of disuse'"`
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
	p := piv.New(log)
	defer p.CloseAll()
	// use FDs passed via socket activation
	ls, err := sockets.Get(validAgents)
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
	idle := time.NewTicker(cmd.IdleTimeout)
	g := errgroup.Group{}
	// start SSH agent if given in agent-type flag
	if _, ok := cmd.AgentTypes["ssh"]; ok {
		log.Debug("starting SSH server")
		g.Go(func() error {
			s := server.NewSSH(log)
			a := ssh.NewAgent(p, log, cmd.LoadKeyfile, cancel)
			err := s.Serve(ctx, a, ls[cmd.AgentTypes["ssh"]], idle, cmd.IdleTimeout)
			if err != nil {
				log.Debug("exiting SSH server", zap.Error(err))
			} else {
				log.Debug("exiting SSH server successfully")
			}
			cancel()
			return err
		})
	}
	// start GPG agent if given in agent-type flag
	home, err := os.UserHomeDir()
	if err != nil {
		log.Warn("couldn't determine $HOME", zap.Error(err))
	}
	fallbackKeys := filepath.Join(home, ".gnupg", "piv-agent.secring")
	if _, ok := cmd.AgentTypes["gpg"]; ok {
		log.Debug("starting GPG server")
		g.Go(func() error {
			s := server.NewGPG(p, &pinentry.PINEntry{}, log, fallbackKeys)
			err := s.Serve(ctx, ls[cmd.AgentTypes["gpg"]], idle, cmd.IdleTimeout)
			if err != nil {
				log.Debug("exiting GPG server", zap.Error(err))
			} else {
				log.Debug("exiting GPG server successfully")
			}
			cancel()
			return err
		})
	}
	exit := time.NewTicker(cmd.ExitTimeout)
loop:
	for {
		select {
		case <-ctx.Done():
			log.Debug("exit done")
			break loop
		case <-idle.C:
			log.Debug("idle timeout")
			cancel()
			break loop
		case <-exit.C:
			log.Debug("exit timeout")
			cancel()
			break loop
		}
	}
	return g.Wait()
}
