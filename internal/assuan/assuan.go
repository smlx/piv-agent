package assuan

//go:generate mockgen -source=assuan.go -destination=../mock/mock_assuan.go -package=mock

import (
	"io"

	"github.com/smlx/piv-agent/internal/fsm"
	"github.com/smlx/piv-agent/internal/key"
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

// PIVAgent is an interface representing the PIV agent methods used by the
// Assuan FSM.
// It is implemented by pivagent.PIVAgent.
type PIVAgent interface {
	SecurityKeys() ([]key.Security, error)
}

type Assuan struct {
	fsm *fsm.Machine
}

// NewFSM initialises a new gpg-agent server assuan FSM.
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
		},
	}
}
