package server

//go:generate mockgen -source=gpg.go -destination=../mock/mock_server_gpg.go -package=mock

import (
	"bytes"
	"context"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/smlx/piv-agent/internal/assuan"
	"github.com/smlx/piv-agent/internal/gpg"
	"github.com/smlx/piv-agent/internal/pivservice"
	"go.uber.org/zap"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
)

// PINEntryService provides an interface to talk to a pinentry program.
type PINEntryService interface {
	GetPGPPassphrase(string) ([]byte, error)
}

// GPG represents a gpg-agent server.
type GPG struct {
	pivService       *pivservice.PIVService
	log              *zap.Logger
	fallbackPrivKeys []*packet.PrivateKey
	pinentry         PINEntryService
}

// LoadFallbackKeys reads the given path and returns any private keys found.
func LoadFallbackKeys(path string) ([]*packet.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("couldn't read keyring %s: %v", path, err)
	}
	reader := packet.NewReader(f)
	var pkt packet.Packet
	var privKeys []*packet.PrivateKey
	for pkt, err = reader.Next(); err != io.EOF; pkt, err = reader.Next() {
		if _, ok := err.(errors.UnsupportedError); ok {
			continue // gpg writes some non-standard cruft
		}
		if err != nil {
			return nil, fmt.Errorf("couldn't get next packet: %v", err)
		}
		k, ok := pkt.(*packet.PrivateKey)
		if !ok {
			continue
		}
		privKeys = append(privKeys, k)
	}
	return privKeys, nil
}

// NewGPG initialises a new gpg-agent server.
func NewGPG(p *pivservice.PIVService, pe PINEntryService, l *zap.Logger, path string) *GPG {
	fallbackPrivKeys, err := LoadFallbackKeys(path)
	if err != nil {
		l.Info("couldn't load fallback RSA keys", zap.Error(err))
	}
	return &GPG{
		pivService: p,
		log:        l,
		// fallback keyfile keys
		fallbackPrivKeys: fallbackPrivKeys,
		pinentry:         pe,
	}
}

// GetKey returns a matching private RSA key if the keygrip matches, and nil
// otherwise.
func (g *GPG) GetKey(keygrip []byte) *rsa.PrivateKey {
	for _, k := range g.fallbackPrivKeys {
		pubKey, ok := k.PublicKey.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if bytes.Equal(keygrip, gpg.KeygripRSA(pubKey)) {
			if k.Encrypted {
				pass, err := g.pinentry.GetPGPPassphrase(
					fmt.Sprintf("%X %X %X %X", k.Fingerprint[:5], k.Fingerprint[5:10],
						k.Fingerprint[10:15], k.Fingerprint[15:]))
				if err != nil {
					g.log.Warn("couldn't get passphrase for key",
						zap.String("fingerprint", k.KeyIdString()), zap.Error(err))
					return nil
				}
				if err = k.Decrypt(pass); err != nil {
					g.log.Warn("couldn't decrypt key",
						zap.String("fingerprint", k.KeyIdString()), zap.Error(err))
				}
			}
			privKey, ok := k.PrivateKey.(*rsa.PrivateKey)
			if !ok {
				g.log.Info("not an RSA key", zap.String("fingerprint", k.KeyIdString()))
				return nil
			}
			return privKey
		}
	}
	return nil
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
			// if the client stops responding for 60 seconds, give up.
			if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
				return fmt.Errorf("couldn't set deadline: %v", err)
			}
			// init protocol state machine
			a := assuan.New(conn, g.pivService, g)
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
