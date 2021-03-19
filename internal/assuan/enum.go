package assuan

import "github.com/smlx/piv-agent/internal/fsm"

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

//go:generate enumer -type=HashAlgo

// HashAlgo represents an Assuan hash function.
type HashAlgo uint64

// Enumeration of all Assuan hashes.
// See gcry_md_algos in libgcrypt.
const (
	invalidHash HashAlgo = 0
	sha512      HashAlgo = 10
)
