package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/smlx/piv-agent/internal/fsm"
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

// handle a valid connection
func (s *GPG) handle(conn net.Conn) error {
	// init protocol state machine
	assuan := s.newAssuanFSM(conn)
	// register connection
	if err := assuan.Occur(fsm.Event(connect)); err != nil {
		return fmt.Errorf("error handling connect: %w", err)
	}
	// parse incoming messages to events
	r := bufio.NewReader(conn)
	var e event
	for {
		line, err := r.ReadBytes(byte('\n'))
		if err != nil {
			if err == io.EOF {
				return nil // connection closed
			}
			return fmt.Errorf("socket read error: %w", err)
		}
		if err := e.UnmarshalText(
			bytes.SplitN(line, []byte(" "), 2)[0]); err != nil {
			return fmt.Errorf("couldn't unmarshal line `%v`: %w", line, err)
		}
		if err := assuan.Occur(fsm.Event(e)); err != nil {
			return fmt.Errorf("error handling event %v: %w", e, err)
		}
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
			// TODO: figure out if this is required
			if err := conn.SetDeadline(time.Now().Add(16 * time.Second)); err != nil {
				return fmt.Errorf("couldn't set deadline: %v", err)
			}
			s.log.Debug("start serving GPG connection")
			return s.handle(conn)
		case <-ctx.Done():
			return nil
		}
	}
}
