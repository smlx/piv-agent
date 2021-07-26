package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/smlx/piv-agent/internal/ssh"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh/agent"
)

// SSH represents an ssh-agent server.
type SSH struct {
	log *zap.Logger
}

// NewSSH initialises a new ssh-agent server.
func NewSSH(l *zap.Logger) *SSH {
	return &SSH{
		log: l,
	}
}

// Serve starts serving signing requests, and returns when the request socket
// is closed, the context is cancelled, or an error occurs.
func (s *SSH) Serve(ctx context.Context, a *ssh.Agent, l net.Listener,
	exit *time.Ticker, timeout time.Duration) error {
	// start serving connections
	conns := accept(s.log, l)
	for {
		select {
		case conn, ok := <-conns:
			if !ok {
				return fmt.Errorf("listen socket closed")
			}
			// reset the exit timer
			exit.Reset(timeout)
			s.log.Debug("start serving SSH connection")
			if err := agent.ServeAgent(a, conn); err != nil {
				if errors.Is(err, io.EOF) {
					s.log.Debug("finish serving connection")
					continue
				}
				return fmt.Errorf("ssh Serve error: %w", err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}
