package assuan

//go:generate mockgen -source=assuan.go -destination=../mock/mock_assuan.go -package=mock

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"io"
	"strconv"

	"github.com/smlx/piv-agent/internal/fsm"
	"github.com/smlx/piv-agent/internal/gpg"
	"github.com/smlx/piv-agent/internal/key"
)

// PIVAgent is an interface representing the PIV agent methods used by the
// Assuan FSM.
// It is implemented by pivagent.PIVAgent.
type PIVAgent interface {
	SecurityKeys() ([]key.Security, error)
}

// Assuan is the Assuan protocol FSM.
type Assuan struct {
	fsm      *fsm.Machine
	keygrips [][]byte
	hashAlgo HashAlgo
	hash     []byte
}

// New initialises a new gpg-agent server assuan FSM.
// It returns a *fsm.Machine configured in the ready state.
func New(w io.Writer, p PIVAgent) *Assuan {
	a := Assuan{}
	a.fsm = &fsm.Machine{
		State: fsm.State(ready),
		Transitions: []fsm.Transition{
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
						a.keygrips = [][]byte{}
						a.hashAlgo = 0
						a.hash = []byte{}
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
					case havekey:
						// HAVEKEY arguments are a list of keygrips
						// if _any_ key is available, we return OK, otherwise
						// No_Secret_Key.
						hk, err := haveKey(p, data)
						if err != nil {
							_, _ = io.WriteString(w, "ERR 1 couldn't check for keygrip\n")
							return fmt.Errorf("couldn't check for keygrip: %v", err)
						}
						if hk {
							_, err = io.WriteString(w, "OK\n")
						} else {
							_, err = io.WriteString(w, "No_Secret_Key\n")
						}
					case keyinfo:
						// KEYINFO arguments are a list of keygrips
						// if _any_ key is available, we return OK, otherwise
						// No_Secret_Key.
						hk, err := haveKey(p, data)
						if err != nil {
							_, _ = io.WriteString(w, "ERR 1 couldn't check for keygrip\n")
							return fmt.Errorf("couldn't check for keygrip: %v", err)
						}
						if hk {
							_, err = io.WriteString(w, "OK\n")
						} else {
							_, err = io.WriteString(w, "No_Secret_Key\n")
						}
					default:
						return fmt.Errorf("unknown event: %v", e)
					}
					return err
				},
			},
			fsm.State(keyIsSet): []func(fsm.Event, ...[]byte) error{
				func(e fsm.Event, data ...[]byte) error {
					var err error
					switch Event(e) {
					case sigkey:
						// SIGKEY has a single argument: a keygrip
						hk, err := haveKey(p, data)
						if err != nil {
							_, _ = io.WriteString(w, "ERR 1 couldn't check for keygrip\n")
							return fmt.Errorf("couldn't check for keygrip: %v", err)
						}
						if hk {
							a.keygrips = append(a.keygrips, data[0])
							_, err = io.WriteString(w, "OK\n")
						} else {
							_, err = io.WriteString(w, "No_Secret_Key\n")
						}
					case setkeydesc:
						// ignore this event since we don't currently use the client's
						// description in the prompt
						_, err = io.WriteString(w, "OK\n")
					default:
						return fmt.Errorf("unknown event: %v", Event(e))
					}
					return err
				},
			},
			fsm.State(hashIsSet): []func(fsm.Event, ...[]byte) error{
				func(e fsm.Event, data ...[]byte) error {
					var err error
					switch Event(e) {
					case sethash:
						// record the algorithm and hash
						h, err := strconv.ParseUint(string(data[0]), 10, 32)
						if err != nil {
							return fmt.Errorf("couldn't parse uint %s: %v", data[0], err)
						}
						a.hashAlgo = HashAlgo(h)
						if !a.hashAlgo.IsAHashAlgo() {
							return fmt.Errorf("invalid hash algorithm value: %v", h)
						}
						a.hash = data[1]
					case pksign:
						// TODO: actually perform the signing
						_, err = io.WriteString(w, "OK\n")
					default:
						return fmt.Errorf("unknown event: %v", Event(e))
					}
					return err
				},
			},
		},
		ErrorOnUnexpectedEvent: true,
	}
	return &a
}

// haveKey returns true if any of the keygrips refer to keys held by the local
// PIVAgent, and false otherwise.
func haveKey(p PIVAgent, keygrips [][]byte) (bool, error) {
	securityKeys, err := p.SecurityKeys()
	if err != nil {
		return false, fmt.Errorf("couldn't get security keys: %v", err)
	}
	for _, sk := range securityKeys {
		for _, signingKey := range sk.SigningKeys {
			ecdsaPubKey, ok := signingKey.Public.(*ecdsa.PublicKey)
			if !ok {
				// TODO: handle other key types
				continue
			}
			thisKeygrip, err := gpg.Keygrip(ecdsaPubKey)
			if err != nil {
				return false, fmt.Errorf("couldn't get keygrip: %v", err)
			}
			for _, kg := range keygrips {
				if bytes.Equal(thisKeygrip, kg) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}
