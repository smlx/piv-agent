package main

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-systemd/activation"
	"github.com/smlx/piv-agent/internal/agent"
	"github.com/smlx/piv-agent/internal/server"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// ServeCmd represents the listen command.
type ServeCmd struct {
	LoadKeyfile bool          `kong:"default=true,help='Load the key file from ~/.ssh/id_ed25519'"`
	ExitTimeout time.Duration `kong:"default=32m,help='Exit after this period to drop transaction and key file passphrase cache'"`
}

// Run the listen command to start listening for ssh-agent requests.
func (cmd *ServeCmd) Run(log *zap.Logger) error {
	log.Info("startup", zap.String("version", version),
		zap.String("build date", date))
	// use systemd socket activation
	ls, err := activation.Listeners()
	if err != nil {
		return fmt.Errorf("cannot retrieve listeners: %w", err)
	}
	if len(ls) != 2 {
		return fmt.Errorf("wrong number of sockets, expected: 2, received: %v",
			len(ls))
	}

	ctx, cancel := context.WithCancel(context.Background())
	exit := time.NewTicker(cmd.ExitTimeout)
	g := errgroup.Group{}
	ssh := server.NewSSH(log)
	a := agent.New(log, cmd.LoadKeyfile)

	g.Go(func() error {
		err := ssh.Serve(ctx, a, ls[0], exit, cmd.ExitTimeout)
		cancel()
		return err
	})

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-exit.C:
			log.Debug("exit timeout")
			cancel()
			break loop
		}
	}
	return g.Wait()
}
