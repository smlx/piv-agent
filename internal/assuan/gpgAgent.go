package assuan

import "github.com/smlx/piv-agent/internal/fsm"

const (
	invalidEvent fsm.Event = iota
	connect
)
const (
	invalidState fsm.State = iota
	ready
	connected
)

// GPGAgent represents the state of the GPGAgent connection.
var GPGAgent = fsm.Machine{
	State: ready,
	Transitions: []fsm.Transition{
		{
			Src:   ready,
			Dst:   connected,
			Event: connect,
		},
	},
	OnEntry: map[fsm.State][]func(fsm.Event){
		connected: []func(fsm.Event){
			func(e fsm.Event) {
				if e == connect {
					// Send "OK Pleased to meet you, process 123456789\n"
				}
			},
		},
	},
}
