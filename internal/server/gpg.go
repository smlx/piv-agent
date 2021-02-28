package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/smlx/piv-agent/internal/assuan"
	"github.com/smlx/piv-agent/internal/pivagent"
	"go.uber.org/zap"
)

// GPG represents an ssh-agent server.
type GPG struct {
	pivAgent *pivagent.PIVAgent
	log      *zap.Logger
}

// NewGPG initialises a new gpg-agent server.
func NewGPG(p *pivagent.PIVAgent, l *zap.Logger) *GPG {
	return &GPG{
		pivAgent: p,
		log:      l,
	}
}

// Serve starts serving signing requests, and returns when the request socket
// is closed, the context is cancelled, or an error occurs.
func (s *GPG) Serve(ctx context.Context, l net.Listener, exit *time.Ticker,
	timeout time.Duration) error {
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
			// if the client stops responding for 16 seconds, give up.
			if err := conn.SetDeadline(time.Now().Add(16 * time.Second)); err != nil {
				return fmt.Errorf("couldn't set deadline: %v", err)
			}
			s.log.Debug("start serving GPG connection")
			// init protocol state machine
			a := assuan.New(conn, s.pivAgent)
			// run the protocol state machine to completion
			return a.Run(conn)
		case <-ctx.Done():
			return nil
		}
	}
}
