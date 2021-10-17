package sockets

import (
	"fmt"
	"net"
	"os"

	"github.com/x13a/go-launch"
)

// Get returns the sockets passed to the process from launchd socket
// activation.
func Get(names []string) ([]net.Listener, error) {
	var listeners []net.Listener
	// get the FDs
	for _, name := range names {
		nameFDs, err := launch.ActivateSocket(name)
		if err != nil {
			return nil, err
		}
		for _, fd := range nameFDs {
			f := os.NewFile(uintptr(fd), name)
			if f == nil {
				return nil, fmt.Errorf("couldn't create file from FD")
			}
			l, err := net.FileListener(f)
			if err != nil {
				return nil, err
			}
			listeners = append(listeners, l)
		}
	}
	return listeners, nil
}
