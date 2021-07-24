package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/smlx/piv-agent/internal/assuan"
	"github.com/smlx/piv-agent/internal/pivservice"
	"go.uber.org/zap"
)

// GPG represents an ssh-agent server.
type GPG struct {
	pivService *pivservice.PIVService
	log        *zap.Logger
}

// NewGPG initialises a new gpg-agent server.
func NewGPG(p *pivservice.PIVService, l *zap.Logger) *GPG {
	return &GPG{
		pivService: p,
		log:        l,
	}
}

// Serve starts serving signing requests, and returns when the request socket
// is closed, the context is cancelled, or an error occurs.
func (g *GPG) Serve(ctx context.Context, l net.Listener, exit *time.Ticker,
	timeout time.Duration) error {
	// start serving connections
	conns := accept(g.log, l)
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
			// init protocol state machine
			a := assuan.New(conn, g.pivService)
			// run the protocol state machine to completion
			// (client severs connection)
			if err := a.Run(conn); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}
