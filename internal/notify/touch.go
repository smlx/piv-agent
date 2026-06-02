// Package notify implements a touch notification system.
package notify

import (
	"context"
	"log/slog"
	"time"

	"github.com/esiqveland/notify"
	"github.com/godbus/dbus/v5"
)

// Notify contains notification configuration.
type Notify struct {
	log *slog.Logger
}

// New initialises a new Notify struct.
func New(log *slog.Logger) *Notify {
	return &Notify{
		log: log,
	}
}

// Message sends a simple notification to the user.
func (n *Notify) Message(summary, body string) error {
	conn, err := dbus.SessionBus()
	if err != nil {
		n.log.Warn("couldn't connect to dbus session bus", slog.Any("error", err))
		return err
	}
	notifier, err := notify.New(conn)
	if err != nil {
		n.log.Warn("couldn't create dbus notifier", slog.Any("error", err))
		return err
	}
	notification := notify.Notification{
		AppName: "PIV Agent",
		Summary: summary,
		Body:    body,
		AppIcon: "dialog-warning",
	}
	notification.SetUrgency(notify.UrgencyNormal)
	_, err = notifier.SendNotification(notification)
	if err != nil {
		n.log.Warn("couldn't send message notification", slog.Any("error", err))
		return err
	}
	go func() {
		time.Sleep(5 * time.Second)
		notifier.Close()
	}()
	return nil
}

// Touch notifies a user to touch the security device. When the returned
// cancellation function is called, the notification is dismissed.
// Touch waits for a brief period before displaying the notification to give
// the signing operation a chance to complete before notifying the user.
func (n *Notify) Touch() context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		conn, err := dbus.SessionBus()
		if err != nil {
			n.log.Warn("couldn't connect to dbus session bus", slog.Any("error", err))
			return
		}
		notifier, err := notify.New(conn)
		if err != nil {
			n.log.Warn("couldn't create dbus notifier", slog.Any("error", err))
			return
		}
		notification := notify.Notification{
			AppName: "PIV Agent",
			Summary: "Waiting for touch",
			Body:    "Please touch your YubiKey now...",
			AppIcon: "dialog-password",
		}
		notification.SetUrgency(notify.UrgencyNormal)
		id, err := notifier.SendNotification(notification)
		if err != nil {
			n.log.Warn("couldn't send touch notification", slog.Any("error", err))
			return
		}
		<-ctx.Done()
		_, err = notifier.CloseNotification(id)
		if err != nil {
			n.log.Warn("couldn't close touch notification", slog.Any("error", err))
		}
		notifier.Close()
	}()
	return cancel
}

// WaitForDevice sends a notification indicating the agent is waiting for a
// YubiKey to be plugged in. It returns a context that is canceled if the user
// dismisses the notification, and a CancelFunc that can be used to dismiss the
// notification once a key is found.
func (n *Notify) WaitForDevice(
	timeout time.Duration,
) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := dbus.SessionBus()
	if err != nil {
		n.log.Warn("couldn't connect to dbus session bus", slog.Any("error", err))
		return ctx, cancel
	}
	var id uint32
	notifier, err := notify.New(
		conn,
		notify.WithOnClosed(func(s *notify.NotificationClosedSignal) {
			if s.ID == id {
				cancel()
			}
		}))
	if err != nil {
		n.log.Warn("couldn't create dbus notifier", slog.Any("error", err))
		return ctx, cancel
	}
	id, err = notifier.SendNotification(notify.Notification{
		AppName:       "PIV Agent",
		Summary:       "Waiting for hardware device",
		Body:          "Plug in YubiKey or dismiss notification to use key file instead",
		AppIcon:       "dialog-password",
		ExpireTimeout: timeout,
	})
	if err != nil {
		n.log.Warn("couldn't send plug-in notification", slog.Any("error", err))
		notifier.Close()
		return ctx, cancel
	}
	return ctx, func() {
		cancel()
		_, err := notifier.CloseNotification(id)
		if err != nil {
			n.log.Warn("couldn't close plug-in notification", slog.Any("error", err))
		}
		notifier.Close()
	}
}
