package assuan

import (
	"crypto"
	"sync"

	"github.com/smlx/fsm"
)

//go:generate enumer -type=Event -text -transform upper

// Event represents an Assuan event.
type Event fsm.Event

// enumeration of all possible events in the assuan FSM
const (
	invalidEvent Event = iota
	connect
	reset
	option
	getinfo
	havekey
	keyinfo
	sigkey
	setkeydesc
	sethash
	pksign
)

//go:generate enumer -type=State -text -transform upper

// State represents an Assuan state.
type State fsm.Event

// Enumeration of all possible states in the assuan FSM.
// connected is the initial state when the client connects.
// keyIsSet indicates that the client has selected a key.
// hashIsSet indicates that the client has selected a hash (and key).
const (
	invalidState State = iota
	ready
	connected
	keyIsSet
	hashIsSet
)

// Assuan is the Assuan protocol FSM.
type Assuan struct {
	fsm.Machine
	mu sync.Mutex
	// data is passed during Occur()
	data [][]byte
	// remaining fields store Assuan internal state
	signingPrivKey crypto.Signer
	hashAlgo       crypto.Hash
	hash           []byte
}

// Occur handles an event occurence.
func (a *Assuan) Occur(e Event, data ...[]byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.data = data
	return a.Machine.Occur(fsm.Event(e))
}

var assuanTransitions = []fsm.Transition{
	{
		Src:   fsm.State(ready),
		Event: fsm.Event(connect),
		Dst:   fsm.State(connected),
	},
	{
		Src:   fsm.State(connected),
		Event: fsm.Event(reset),
		Dst:   fsm.State(connected),
	},
	{
		Src:   fsm.State(connected),
		Event: fsm.Event(option),
		Dst:   fsm.State(connected),
	},
	{
		Src:   fsm.State(connected),
		Event: fsm.Event(getinfo),
		Dst:   fsm.State(connected),
	},
	{
		Src:   fsm.State(connected),
		Event: fsm.Event(havekey),
		Dst:   fsm.State(connected),
	},
	{
		Src:   fsm.State(connected),
		Event: fsm.Event(keyinfo),
		Dst:   fsm.State(connected),
	},
	{
		Src:   fsm.State(connected),
		Event: fsm.Event(sigkey),
		Dst:   fsm.State(keyIsSet),
	},
	{
		Src:   fsm.State(keyIsSet),
		Event: fsm.Event(setkeydesc),
		Dst:   fsm.State(keyIsSet),
	},
	{
		Src:   fsm.State(keyIsSet),
		Event: fsm.Event(sethash),
		Dst:   fsm.State(hashIsSet),
	},
	{
		Src:   fsm.State(hashIsSet),
		Event: fsm.Event(pksign),
		Dst:   fsm.State(hashIsSet),
	},
}