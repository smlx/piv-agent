package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
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
	listeners, err := activation.ListenersWithNames()
	if err != nil {
		return fmt.Errorf("cannot retrieve listeners: %w", err)
	}
	if len(listeners) > 2 {
		return fmt.Errorf(
			"unexpected number of listeners, expected: <=2, received: %v",
			len(listeners))
	}
	// start the exit timer
	exitTicker := time.NewTicker(cmd.ExitTimeout)
	// start serving connections
	sshConns := make(chan net.Conn)
	gopassConns := make(chan net.Conn)
	// unwrap the singular map key/value to the the array of sockets
	for name, sock := range listeners {
		if len(sock) != 1 {
			return fmt.Errorf(
				"unexpected number of sockets from %v. expected: 1, received: %v",
				name, len(listeners))
		}
		log.Debug("connection on socket", zap.String("name", name))
		if strings.Contains(name, "gopass") {
			go accept(sock[0], gopassConns, log)
		} else {
			go accept(sock[0], sshConns, log)
		}
	}

	a := pivagent.New(log, cmd.LoadKeyfile)
	for {
		select {
		case conn, ok := <-sshConns:
			if !ok {
				return fmt.Errorf("ssh listen socket closed")
			}
			exitTicker.Reset(cmd.ExitTimeout)
			log.Debug("start serving ssh connection")
			if err = agent.ServeAgent(a, conn); err != nil {
				if errors.Is(err, io.EOF) {
					log.Debug("finish serving ssh connection")
					continue
				}
				return fmt.Errorf("serveAgent error: %w", err)
			}
		case conn, ok := <-gopassConns:
			if !ok {
				return fmt.Errorf("gopass listen socket closed")
			}
			exitTicker.Reset(cmd.ExitTimeout)
			log.Debug("start serving gopass connection")
			if err = agent.ServeAgent(a, conn); err != nil {
				if errors.Is(err, io.EOF) {
					log.Debug("finish serving gopass connection")
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

func accept(l net.Listener, conn chan<- net.Conn, log *zap.Logger) {
	for {
		c, err := l.Accept()
		if err != nil {
			log.Error("accept error", zap.Error(err))
			close(conn)
			return
		}
		conn <- c
	}
}
