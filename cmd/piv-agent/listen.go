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
		log.Error("unexpected number of sockets", zap.Int("expected", 1),
			zap.Int("received", len(listeners)))
	}
	// open the security key
	keys, err := getAllSecurityKeys(log)
	if err != nil {
		return fmt.Errorf("couldn't get security key: %w", err)
	}
	return cmd.listen(&Agent{securityKeys: keys}, listeners[0])
}

func (cmd *ServeCmd) listen(k *Agent, s net.Listener) error {
	// TODO: fix up this logic
	for {
		conn, err := s.Accept()
		if err != nil {
			return fmt.Errorf("accpet error: %w", err)
		}
		if err = agent.ServeAgent(k, conn); err != nil {
			return fmt.Errorf("serveAgent error: %w", err)
		}
	}
}
