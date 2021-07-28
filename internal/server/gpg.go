package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/smlx/piv-agent/internal/assuan"
	"github.com/smlx/piv-agent/internal/gpg"
	"github.com/smlx/piv-agent/internal/pivservice"
	"go.uber.org/zap"
)

// GPG represents a gpg-agent server.
type GPG struct {
	log            *zap.Logger
	pivService     *pivservice.PIVService
	keyfileService *gpg.KeyfileService // fallback keyfile keys
}

// NewGPG initialises a new gpg-agent server.
func NewGPG(piv *pivservice.PIVService, pinentry gpg.PINEntryService,
	log *zap.Logger, path string) *GPG {
	kfs, err := gpg.NewKeyfileService(log, pinentry, path)
	if err != nil {
		log.Info("couldn't load keyfiles", zap.String("path", path), zap.Error(err))
	}
	return &GPG{
		pivService:     piv,
		log:            log,
		keyfileService: kfs,
	}
}

// Serve starts serving signing requests, and returns when the request socket
// is closed, the context is cancelled, or an error occurs.
func (g *GPG) Serve(ctx context.Context, l net.Listener, exit *time.Ticker,
	timeout time.Duration) error {
	// start serving connections
	conns := accept(g.log, l)
	g.log.Debug("accepted gpg-agent connection")
	for {
		select {
		case conn, ok := <-conns:
			if !ok {
				return fmt.Errorf("listen socket closed")
			}
			// reset the exit timer
			exit.Reset(timeout)
			// if the client stops responding for 60 seconds, give up.
			if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
				return fmt.Errorf("couldn't set deadline: %v", err)
			}
			// init protocol state machine
			a := assuan.New(conn, g.log, g.pivService, g.keyfileService)
			// run the protocol state machine to completion
			// (client severs connection)
			if err := a.Run(); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}
