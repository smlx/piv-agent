package main

import (
	"fmt"
	"net"

	"github.com/coreos/go-systemd/activation"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh/agent"
)

// ServeCmd represents the listen command.
type ServeCmd struct{}

// Run the listen command to start listening for ssh-agent requests.
func (cmd *ServeCmd) Run() error {
	log, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("couldn't init logger: %w", err)
	}
	defer log.Sync()
	log.Info("startup", zap.String("version", version),
		zap.String("buildTime", buildTime))
	// use systemd socket activation
	listeners, err := activation.Listeners()
	if err != nil {
		log.Error("cannot retrieve listeners", zap.Error(err))
	}
	if len(listeners) != 1 {
		return fmt.Errorf("unexpected number of sockets, expected: 1, received: %v",
			len(listeners))
	}
	// open the security key
	keys, err := getAllSecurityKeys(log)
	if err != nil {
		return fmt.Errorf("couldn't get security key: %w", err)
	}
	return cmd.serve(&Agent{securityKeys: keys}, listeners[0])
}

func (cmd *ServeCmd) serve(a *Agent, s net.Listener) error {
	// TODO: fix up this logic
	for {
		conn, err := s.Accept()
		if err != nil {
			return fmt.Errorf("accpet error: %w", err)
		}
		if err = agent.ServeAgent(a, conn); err != nil {
			return fmt.Errorf("serveAgent error: %w", err)
		}
	}
}
