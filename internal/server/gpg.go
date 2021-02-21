package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/davecgh/go-spew/spew"
	"go.uber.org/zap"
)

// GPG represents an ssh-agent server.
type GPG struct {
	log *zap.Logger
}

// NewGPG initialises a new gpg-agent server.
func NewGPG(l *zap.Logger) *GPG {
	return &GPG{
		log: l,
	}
}

// Serve starts serving signing requests, and returns when the request socket
// is closed, the context is cancelled, or an error occurs.
func (s *GPG) Serve(ctx context.Context, l net.Listener,
	exit *time.Ticker, timeout time.Duration) error {
	// start serving connections
	conns := accept(ctx, s.log, l)
	for {
		select {
		case conn, ok := <-conns:
			if !ok {
				return fmt.Errorf("listen socket closed")
			}
			// reset the exit timer
			exit.Reset(timeout)
			s.log.Debug("start serving GPG connection")
			conn.SetDeadline(time.Now().Add(16 * time.Second))
			_, err := io.WriteString(conn, "OK Pleased to meet you, process 123456789\n")
			s.log.Debug("write done")
			if err != nil {
				s.log.Error("couldn't write to socket", zap.Error(err))
			}
			buf := bytes.Buffer{}
			_, err = io.Copy(&buf, conn)
			s.log.Debug("copy done")
			if _, ok := err.(*net.OpError); !ok && err != nil {
				s.log.Error("couldn't read from socket", zap.Error(err))
			}
			spew.Dump(err)
			spew.Dump(buf)
		case <-ctx.Done():
			return nil
		}
	}
}
