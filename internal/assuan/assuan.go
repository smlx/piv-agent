package assuan

//go:generate mockgen -source=assuan.go -destination=../mock/mock_assuan.go -package=mock

import (
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
			},
			OnEntry: map[fsm.State][]func(fsm.Event) error{
				fsm.State(connected): []func(fsm.Event) error{
					func(e fsm.Event) error {
						if e == fsm.Event(connect) {
							_, err := io.WriteString(w,
								"OK Pleased to meet you, process 123456789\n")
							return err
						}
						return nil
					},
				},
			},
			ErrorOnUnexpectedEvent: true,
		},
	}
}
