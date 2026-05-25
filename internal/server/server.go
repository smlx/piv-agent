package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"filippo.io/age/plugin"
	"github.com/smlx/piv-agent/internal/age"
	"github.com/smlx/piv-agent/internal/notify"
	"github.com/smlx/piv-agent/internal/piv"
	"github.com/smlx/piv-agent/internal/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const connTimeout = 4 * time.Minute

// accept connections in a goroutine and return them on a channel
func accept(log *slog.Logger, l net.Listener) <-chan net.Conn {
	conns := make(chan net.Conn)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				log.Error("accept error", slog.Any("error", err))
				close(conns)
				return
			}
			conns <- c
		}
	}()
	return conns
}

// Age represents an age-plugin server.
type Age struct {
	log       *slog.Logger
	piv       *piv.KeyService
	fetchSeed age.SeedFetcher
	notify    *notify.Notify
}

// NewAge initialises a new age-plugin server.
func NewAge(log *slog.Logger, piv *piv.KeyService, fetchSeed age.SeedFetcher, notify *notify.Notify) *Age {
	return &Age{
		log:       log,
		piv:       piv,
		fetchSeed: fetchSeed,
		notify:    notify,
	}
}

// Serve starts serving age-plugin requests, and returns when the request socket
// is closed, the context is cancelled, or an error occurs.
func (a *Age) Serve(ctx context.Context, l net.Listener, exit *time.Ticker,
	timeout time.Duration) error {
	// start serving connections
	conns := accept(a.log, l)
	for {
		select {
		case conn, ok := <-conns:
			if !ok {
				return fmt.Errorf("listen socket closed")
			}
			a.log.Debug("accepted age-agent connection")
			// reset the idle exit timer
			exit.Reset(timeout)
			// if the client takes too long, give up
			if err := conn.SetDeadline(time.Now().Add(connTimeout)); err != nil {
				return fmt.Errorf("couldn't set deadline: %v", err)
			}
			go func() {
				defer conn.Close()
				// read the state machine
				reader := bufio.NewReader(conn)
				sm, err := reader.ReadString('\n')
				if err != nil {
					a.log.Error("couldn't read age plugin state machine",
						slog.Any("error", err))
					return
				}
				sm = strings.TrimSpace(sm)
				// set up the plugin
				p, err := plugin.New("piv-agent")
				if err != nil {
					a.log.Error("couldn't create age plugin", slog.Any("error", err))
					return
				}
				p.HandleRecipient(age.HandleRecipient())
				p.HandleIdentity(age.HandleIdentity(a.piv, a.fetchSeed, a.notify))
				p.SetIO(reader, conn, conn)
				// run the relevant state machine
				var exitCode int
				switch sm {
				case "recipient-v1":
					exitCode = p.RecipientV1()
				case "identity-v1":
					exitCode = p.IdentityV1()
				default:
					a.log.Error("invalid age plugin state machine", slog.String("sm", sm))
					return
				}
				// handle errors
				if exitCode != 0 {
					a.log.Error("age plugin error", slog.Int("exit_code", exitCode))
				}
				a.log.Debug("finish serving age-agent connection")
			}()
		case <-ctx.Done():
			return nil
		}
	}
}

// SSH represents an ssh-agent server.
type SSH struct {
	log *slog.Logger
}

// NewSSH initialises a new ssh-agent server.
func NewSSH(l *slog.Logger) *SSH {
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
					s.log.Error("ssh-agent error", slog.Any("error", err))
				}
				s.log.Debug("finish serving ssh-agent connection")
			}()
		case <-ctx.Done():
			return nil
		}
	}
}
