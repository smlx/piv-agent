package server

import (
	"io"
	"net"

	"github.com/smlx/piv-agent/internal/fsm"
)

//go:generate enumer -type=event -text -transform upper
type event fsm.Event

//go:generate enumer -type=state -text -transform upper
type state fsm.Event

// enumeration of all possible events in the assuan FSM
const (
	invalidEvent event = iota
	connect
)

// enumeration of all possible states in the assuan FSM
const (
	invalidState state = iota
	ready
	connected
)

// newAssuanFSM initialises a new gpg-agent server FSM.
// It returns a *fsm.Machine configured in the ready state.
func newAssuanFSM(conn net.Conn) *fsm.Machine {
	return &fsm.Machine{
		State: fsm.State(ready),
		Transitions: []fsm.Transition{
			{
				Src:   fsm.State(ready),
				Dst:   fsm.State(connected),
				Event: fsm.Event(connect),
			},
		},
		OnEntry: map[fsm.State][]func(fsm.Event) error{
			fsm.State(connected): []func(fsm.Event) error{
				func(e fsm.Event) error {
					if e == fsm.Event(connect) {
						_, err := io.WriteString(conn,
							"OK Pleased to meet you, process 123456789\n")
						return err
					}
					return nil
				},
			},
		},
	}
}
