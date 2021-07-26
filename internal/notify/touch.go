package notify

import (
	"context"
	"time"

	"github.com/gen2brain/beeep"
	"go.uber.org/zap"
)

const waitTime = 6 * time.Second

// Touch starts a goroutine, and waits for a short period. If the returned
// CancelFunc has not been called it sends a notification to remind the user to
// physically touch the Security Key.
func Touch(log *zap.Logger) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.NewTimer(waitTime)
	go func() {
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
			err := beeep.Alert("Security Key Agent", "Waiting for touch...", "")
			if err != nil && log != nil {
				log.Warn("couldn't send touch notification", zap.Error(err))
			}
		}
	}()
	return cancel
}
