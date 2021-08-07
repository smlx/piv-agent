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

// GPG represents a gpg-agent server.
type GPG struct {
	log           *zap.Logger
	pivKeyService *piv.KeyService
	gpgKeyService *gpg.KeyService // fallback keyfile keys
}

// NewGPG initialises a new gpg-agent server.
func NewGPG(piv *piv.KeyService, pinentry gpg.PINEntryService,
	log *zap.Logger, path string) *GPG {
	kfs, err := gpg.New(log, pinentry, path)
	if err != nil {
		log.Info("couldn't load keyfiles", zap.String("path", path), zap.Error(err))
	}
	return &GPG{
		log:           log,
		pivKeyService: piv,
		gpgKeyService: kfs,
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
			a := assuan.New(conn, g.log, g.pivKeyService, g.gpgKeyService)
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
