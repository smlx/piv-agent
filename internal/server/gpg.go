package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/smlx/piv-agent/internal/assuan"
	"github.com/smlx/piv-agent/internal/keyservice/gpg"
	"github.com/smlx/piv-agent/internal/keyservice/piv"
	"go.uber.org/zap"
)

const connTimeout = 4 * time.Minute

// GPG represents a gpg-agent server.
type GPG struct {
	log           *zap.Logger
	pivKeyService *piv.KeyService
	gpgKeyService *gpg.KeyService // fallback keyfile keys
}

// NewGPG initialises a new gpg-agent server.
func NewGPG(piv *piv.KeyService, pinentry gpg.PINEntryService,
	log *zap.Logger, path string) *GPG {
	return &GPG{
		log:           log,
		pivKeyService: piv,
		gpgKeyService: gpg.New(log, pinentry, path),
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
			g.log.Debug("accepted gpg-agent connection")
			// reset the exit timer
			exit.Reset(timeout)
			// if the client takes too long, give up
			if err := conn.SetDeadline(time.Now().Add(connTimeout)); err != nil {
				return fmt.Errorf("couldn't set deadline: %v", err)
			}
			// init protocol state machine
			a := assuan.New(conn, g.log, g.pivKeyService, g.gpgKeyService)
			// this goroutine will exit by either:
			// * client severs connection (the usual case)
			// * conn deadline reached (client stopped responding)
			//   err will be non-nil in this case.
			go func() {
				// run the protocol state machine to completion
				if err := a.Run(ctx); err != nil {
					g.log.Error("gpg-agent error", zap.Error(err))
				}
			}()
		case <-ctx.Done():
			return nil
		}
	}
}
