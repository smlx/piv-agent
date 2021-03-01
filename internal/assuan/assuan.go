package assuan

//go:generate mockgen -source=assuan.go -destination=../mock/mock_assuan.go -package=mock

import (
	"bytes"
	"fmt"
	"io"

	"github.com/smlx/piv-agent/internal/fsm"
	"github.com/smlx/piv-agent/internal/key"
)

//go:generate enumer -type=Event -text -transform upper

// Event represents an Assuan event.
type Event fsm.Event

//go:generate enumer -type=State -text -transform upper

// State represents an Assuan state.
type State fsm.Event

// enumeration of all possible events in the assuan FSM
const (
	invalidEvent Event = iota
	connect
	reset
	option
	getinfo
)

// enumeration of all possible states in the assuan FSM
const (
	invalidState State = iota
	ready
	connected
)

// PIVAgent is an interface representing the PIV agent methods used by the
// Assuan FSM.
// It is implemented by pivagent.PIVAgent.
type PIVAgent interface {
	SecurityKeys() ([]key.Security, error)
}

// Assuan is the Assuan protocol FSM.
type Assuan struct {
	fsm *fsm.Machine
}

// New initialises a new gpg-agent server assuan FSM.
// It returns a *fsm.Machine configured in the ready state.
func New(w io.Writer, p PIVAgent) *Assuan {
	return &Assuan{
		fsm: &fsm.Machine{
			State: fsm.State(ready),
			Transitions: []fsm.Transition{
				{
					Src:   fsm.State(ready),
					Dst:   fsm.State(connected),
					Event: fsm.Event(connect),
				},
				{
					Src:   fsm.State(connected),
					Dst:   fsm.State(connected),
					Event: fsm.Event(reset),
				},
				{
					Src:   fsm.State(connected),
					Dst:   fsm.State(connected),
					Event: fsm.Event(option),
				},
				{
					Src:   fsm.State(connected),
					Dst:   fsm.State(connected),
					Event: fsm.Event(getinfo),
				},
			},
			OnEntry: map[fsm.State][]func(fsm.Event, ...[]byte) error{
				fsm.State(connected): []func(fsm.Event, ...[]byte) error{
					func(e fsm.Event, data ...[]byte) error {
						var err error
						switch Event(e) {
						case connect:
							// acknowledge connection using the format expected by the client
							_, err = io.WriteString(w,
								"OK Pleased to meet you, process 123456789\n")
						case reset:
							// TODO: reset state
							_, err = io.WriteString(w, "OK\n")
						case option:
							// ignore option values - piv-agent doesn't use them
							_, err = io.WriteString(w, "OK\n")
						case getinfo:
							if bytes.Equal(data[0], []byte("version")) {
								// masquerade as a compatible gpg-agent
								_, err = io.WriteString(w, "D 2.2.20\nOK\n")
							} else {
								err = fmt.Errorf("unknown getinfo command: %q", data[0])
							}
						}
						return err
					},
				},
			},
			ErrorOnUnexpectedEvent: true,
		},
	}
}
