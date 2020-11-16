package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/coreos/go-systemd/activation"
	pivagent "github.com/smlx/piv-agent/internal/agent"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh/agent"
)

// ServeCmd represents the listen command.
type ServeCmd struct {
	Debug       bool          `kong:"help='Enable debug logging'"`
	LoadKeyfile bool          `kong:"default=true,help='Load the key file from ~/.ssh/id_ed25519'"`
	ExitTimeout time.Duration `kong:"default=32m,help='Exit after this period to drop transaction and key file passphrase cache'"`
}

const exitTimeout = 32 * time.Minute

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
		return fmt.Errorf("cannot retrieve listeners: %w", err)
	}
	if len(listeners) != 1 {
		return fmt.Errorf("unexpected number of sockets, expected: 1, received: %v",
			len(listeners))
	}
	// start the exit timer
	exitTicker := time.NewTicker(cmd.ExitTimeout)
	// start serving connections
	newConns := make(chan net.Conn)
	go func(l net.Listener, log *zap.Logger) {
		for {
			c, err := l.Accept()
			if err != nil {
				log.Error("accept error", zap.Error(err))
				close(newConns)
				return
			}
			newConns <- c
		}
	}(listeners[0], log)

	a := pivagent.New(log, cmd.LoadKeyfile)
	for {
		select {
		case conn, ok := <-newConns:
			if !ok {
				return fmt.Errorf("listen socket closed")
			}
			// reset the exit timer
			exitTicker.Reset(cmd.ExitTimeout)
			log.Debug("start serving connection")
			if err = agent.ServeAgent(a, conn); err != nil {
				if errors.Is(err, io.EOF) {
					log.Debug("finish serving connection")
					continue
				}
				return fmt.Errorf("serveAgent error: %w", err)
			}
		case <-exitTicker.C:
			log.Debug("exit timeout")
			return nil
		}
	}
}
