package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/smlx/piv-agent/internal/keyservice/piv"
	"github.com/smlx/piv-agent/internal/notify"
	"github.com/smlx/piv-agent/internal/pinentry"
	"github.com/smlx/piv-agent/internal/server"
	"github.com/smlx/piv-agent/internal/sockets"
	"github.com/smlx/piv-agent/internal/ssh"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// agentTypeFlag is the --agent-type flag
type agentTypeFlag map[string]uint

// validAgents is the list of agents supported by piv-agent.
var validAgents = []string{"ssh", "gpg", "age"}

// ServeCmd represents the listen command.
type ServeCmd struct {
	LoadKeyfile          bool          `kong:"default=true,help='Load the key file from ~/.ssh/id_ed25519'"`
	ExitTimeout          time.Duration `kong:"default=12h,help='Exit after this period to drop transaction and key file passphrase cache, even if service is in use'"`
	IdleTimeout          time.Duration `kong:"default=128m,help='Exit after this period of disuse'"`
	TouchNotifyDelay     time.Duration `kong:"default=6s,help='Display a notification after this period when waiting for a touch'"`
	PinentryBinaryName   string        `kong:"default='pinentry',help='Pinentry binary which will be used, must be in $PATH'"`
	AgentTypes           agentTypeFlag `kong:"default='ssh=0;gpg=1;age=2',help='Agent types to handle'"`
	CredentialsDirectory string        `kong:"required,env='CREDENTIALS_DIRECTORY',help='Path to the systemd credentials directory'"`
}

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

// fetchSeed reads the ML-KEM seed from the credentials directory.
func (cmd *ServeCmd) fetchSeed(fileID [8]byte) ([]byte, error) {
	filename := hex.EncodeToString(fileID[:])
	seedPath := filepath.Join(cmd.CredentialsDirectory, "seeds_"+filename)

	seed, err := os.ReadFile(seedPath)
	if err != nil {
		return nil, fmt.Errorf("couldn't read seed file %s: %v", seedPath, err)
	}
	return seed, nil
}

// Run the listen command to start listening for requests.
func (cmd *ServeCmd) Run(log *zap.Logger) error {
	log.Info("startup", zap.String("version", version),
		zap.String("build date", date))
	pe := pinentry.New(cmd.PinentryBinaryName)
	p := piv.New(log, pe)
	defer p.CloseAll()
	// use FDs passed via socket activation
	ls, err := sockets.Get(validAgents)
	if err != nil {
		return fmt.Errorf("cannot retrieve listeners: %v", err)
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
	n := notify.New(log, cmd.TouchNotifyDelay)
	g := errgroup.Group{}
	// start SSH agent if given in agent-type flag
	if _, ok := cmd.AgentTypes["ssh"]; ok {
		log.Debug("starting SSH server")
		g.Go(func() error {
			s := server.NewSSH(log)
			a := ssh.NewAgent(p, pe, log, cmd.LoadKeyfile, n, cancel)
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
			s := server.NewGPG(p, pe, log, fallbackKeys, n)
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
	// start age agent if given in agent-type flag
	if _, ok := cmd.AgentTypes["age"]; ok {
		log.Debug("starting age server")
		g.Go(func() error {
			s := server.NewAge(log, p, cmd.fetchSeed)
			err := s.Serve(ctx, ls[cmd.AgentTypes["age"]], idle, cmd.IdleTimeout)
			if err != nil {
				log.Debug("exiting age server", zap.Error(err))
			} else {
				log.Debug("exiting age server successfully")
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
