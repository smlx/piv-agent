package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/coreos/go-systemd/activation"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh/agent"
)

// ServeCmd represents the listen command.
type ServeCmd struct {
	Debug       bool `kong:"help='Enable debug logging'"`
	LoadKeyfile bool `kong:"default=true,help='Load the key file from ~/.ssh/id_ed25519'"`
}

// Run the listen command to start listening for ssh-agent requests.
func (cmd *ServeCmd) Run() error {
	var log *zap.Logger
	var err error
	if cmd.Debug {
		log, err = zap.NewDevelopment()
	} else {
		log, err = zap.NewProduction()
	}
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
	// start serving connections
	a := Agent{log: log, loadKeyfile: cmd.LoadKeyfile}
	for {
		conn, err := listeners[0].Accept()
		if err != nil {
			return fmt.Errorf("accept error: %w", err)
		}
		if err = agent.ServeAgent(&a, conn); err != nil {
			if errors.Is(err, io.EOF) {
				continue
			}
			return fmt.Errorf("serveAgent error: %w", err)
		}
	}
}
