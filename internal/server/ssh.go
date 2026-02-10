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
			s.log.Debug("accepted ssh-agent connection")
			// reset the idle exit timer
			exit.Reset(timeout)
			// if the client takes too long, give up
			if err := conn.SetDeadline(time.Now().Add(connTimeout)); err != nil {
				return fmt.Errorf("couldn't set deadline: %v", err)
			}
			// this goroutine will exit by either:
			// * client severs connection (the usual case)
			// * conn deadline reached (client stopped responding)
			//   err will be non-nil in this case.
			go func() {
				if err := agent.ServeAgent(a, conn); err != nil && !errors.Is(err, io.EOF) {
					s.log.Error("ssh-agent error", zap.Error(err))
				}
				s.log.Debug("finish serving ssh-agent connection")
			}()
		case <-ctx.Done():
			return nil
		}
	}
}
