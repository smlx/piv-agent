package main

import (
	"log/slog"
	"time"

	pivgo "github.com/go-piv/piv-go/v2/piv"
	"github.com/smlx/piv-agent/internal/notify"
)

// WaitForDeviceCmd represents the wait-for-device command.
type WaitForDeviceCmd struct{}

// Run the wait-for-device command.
func (cmd *WaitForDeviceCmd) Run(log *slog.Logger) error {
	cards, err := pivgo.Cards()
	if err != nil {
		return err
	}
	if len(cards) > 0 {
		return nil
	}

	n := notify.New(log)
	ctx, cancel := n.WaitForDevice(60 * time.Second)
	defer cancel()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cards, err = pivgo.Cards()
			if err == nil && len(cards) > 0 {
				return nil
			}
		}
	}
}
