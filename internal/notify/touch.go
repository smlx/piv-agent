// Package notify implements a touch notification system.
package notify

import (
	"context"
	"log/slog"
	"time"

	"github.com/gen2brain/beeep"
)

// Notify contains touch notification configuration.
type Notify struct {
	log         *slog.Logger
	notifyDelay time.Duration
}

// New initialises a new Notify struct.
func New(log *slog.Logger, notifyDelay time.Duration) *Notify {
	return &Notify{
		log:              log,
		touchNotifyDelay: touchNotifyDelay,
	}
}

// Touch starts a goroutine, and waits for a short period. If the returned
// CancelFunc has not been called it sends a notification to remind the user to
// physically touch the Security Key.
func (n *Notify) Touch() context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.NewTimer(n.touchNotifyDelay)
	go func() {
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
			err := beeep.Alert("Security Key Agent", "Waiting for touch...", "")
			if err != nil {
				n.log.Warn("couldn't send touch notification", slog.Any("error", err))
			}
		}
	}()
	return cancel
}
