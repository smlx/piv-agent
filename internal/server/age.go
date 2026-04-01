package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/smlx/piv-agent/internal/age"
	"github.com/smlx/piv-agent/internal/keyservice/piv"
	"go.uber.org/zap"

	"filippo.io/age/plugin"
)

// Age represents an age-plugin server.
type Age struct {
	log       *zap.Logger
	piv       *piv.KeyService
	fetchSeed age.SeedFetcher
}

// NewAge initialises a new age-plugin server.
func NewAge(log *zap.Logger, piv *piv.KeyService, fetchSeed age.SeedFetcher) *Age {
	return &Age{
		log:       log,
		piv:       piv,
		fetchSeed: fetchSeed,
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
					a.log.Error("couldn't read age plugin state machine", zap.Error(err))
					return
				}
				sm = strings.TrimSpace(sm)
				// set up the plugin
				p, err := plugin.New("piv-agent")
				if err != nil {
					a.log.Error("couldn't create age plugin", zap.Error(err))
					return
				}
				p.HandleRecipient(age.HandleRecipient())
				p.HandleIdentity(age.HandleIdentity(a.piv, a.fetchSeed))
				p.SetIO(reader, conn, conn)
				// run the relevant state machine
				var exitCode int
				switch sm {
				case "recipient-v1":
					exitCode = p.RecipientV1()
				case "identity-v1":
					exitCode = p.IdentityV1()
				default:
					a.log.Error("invalid age plugin state machine", zap.String("sm", sm))
					return
				}
				// handle errors
				if exitCode != 0 {
					a.log.Error("age plugin error", zap.Int("exit_code", exitCode))
				}
				a.log.Debug("finish serving age-agent connection")
			}()
		case <-ctx.Done():
			return nil
		}
	}
}
