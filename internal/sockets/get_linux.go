package sockets

import (
	"net"

	"github.com/coreos/go-systemd/activation"
)

// Get returns the sockets passed to the process from systemd socket
// activation.
func Get(_ []string) ([]net.Listener, error) {
	return activation.Listeners()
}
