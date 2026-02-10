// Package assuan implements an libgcrypt Assuan protocol server.
package assuan

//go:generate go tool mockgen -source=assuan.go -destination=../mock/mock_assuan.go -package=mock

import (
	"bufio"
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/smlx/fsm"
	"github.com/smlx/piv-agent/internal/notify"
	"go.uber.org/zap"
)

// version indicates the version of gpg-agent to emulate.
// The gpg CLI client will emit a warning if this is lower than the version of
// the gpg client itself.
const version = "2.4.8"

// The KeyService interface provides functions used by the Assuan FSM.
type KeyService interface {
	Name() string
	HaveKey([][]byte) (bool, []byte, error)
	Keygrips() ([][]byte, error)
	GetSigner([]byte) (crypto.Signer, error)
	GetDecrypter([]byte) (crypto.Decrypter, error)
}

// New initialises a new gpg-agent server assuan FSM.
// It returns a *fsm.Machine configured in the ready state.
func New(rw io.ReadWriter, log *zap.Logger, n *notify.Notify,
	ks ...KeyService) *Assuan {
	var signature []byte
	var keygrips, hash [][]byte
	assuan := Assuan{
		notify: n,
		reader: bufio.NewReader(rw),
		Machine: fsm.Machine{
			State:       fsm.State(ready),
			Transitions: assuanTransitions,
		},
	}
	assuan.OnEntry = map[fsm.State][]fsm.TransitionFunc{
		fsm.State(connected): {
			func(e fsm.Event, _ fsm.State) error {
				var err error
				switch Event(e) {
				case connect:
					// acknowledge connection using the format expected by the client
					_, err = io.WriteString(rw,
						"OK Pleased to meet you, process 123456789\n")
				case reset:
					assuan.reset()
					_, err = io.WriteString(rw, "OK\n")
				case option:
					// ignore option values - piv-agent doesn't use them
					_, err = io.WriteString(rw, "OK\n")
				case getinfo:
					if bytes.Equal(assuan.data[0], []byte("version")) {
						// masquerade as a compatible gpg-agent
						_, err = fmt.Fprintf(rw, "D %s\nOK\n", version)
					} else {
						err = fmt.Errorf("unknown getinfo command: %q", assuan.data[0])
					}
				case havekey:
					err = assuan.havekey(rw, ks)
				case keyinfo:
					err = doKeyinfo(rw, assuan.data, ks)
				case scd:
					// ignore scdaemon requests
					_, err = io.WriteString(rw, "ERR 100696144 No such device <SCD>\n")
				case readkey:
					// READKEY argument is a keygrip, optionally prefixed by "--".
					if bytes.Equal(assuan.data[0], []byte("--")) {
						assuan.data = assuan.data[1:]
					}
					// return information about the given key
					keygrips, err = hexDecode(assuan.data...)
					if err != nil {
						return fmt.Errorf("couldn't decode keygrips: %v", err)
					}
					var signer crypto.Signer
					for _, k := range ks {
						signer, err = k.GetSigner(keygrips[0])
						if err == nil {
							break
						}
					}
					if signer == nil {
						_, _ = io.WriteString(rw, "ERR 1 couldn't match keygrip\n")
						return fmt.Errorf("couldn't match keygrip: %v", err)
					}
					var data string
					data, err = readKeyData(signer.Public())
					if err != nil {
						_, _ = io.WriteString(rw, "ERR 1 couldn't get key data\n")
						return fmt.Errorf("couldn't get key data: %v", err)
					}
					_, err = io.WriteString(rw, data)
				case setkeydesc:
					// ignore this event since we don't currently use the client's
					// description in the prompt
					_, err = io.WriteString(rw, "OK\n")
				case passwd:
					// ignore this event since we assume that if the key is decrypted the
					// user has permissions
					_, err = io.WriteString(rw, "OK\n")
				default:
					return fmt.Errorf("unknown event: %v", e)
				}
				return err
			},
		},
		fsm.State(signingKeyIsSet): {
			func(e fsm.Event, _ fsm.State) error {
				var err error
				switch Event(e) {
				case sigkey:
					// SIGKEY has a single argument: a keygrip indicating the key which
					// will be used for subsequent signing operations
					keygrips, err = hexDecode(assuan.data...)
					if err != nil {
						return fmt.Errorf("couldn't decode keygrips: %v", err)
					}
					for _, k := range ks {
						assuan.signer, err = k.GetSigner(keygrips[0])
						if err == nil {
							break
						}
					}
					if err != nil {
						_, _ = io.WriteString(rw, "ERR 1 couldn't get key for keygrip\n")
						return fmt.Errorf("couldn't get key for keygrip: %v", err)
					}
					_, err = io.WriteString(rw, "OK\n")
				case setkeydesc:
					// ignore this event since we don't currently use the client's
					// description in the prompt
					_, err = io.WriteString(rw, "OK\n")
				default:
					return fmt.Errorf("unknown event: %v", Event(e))
				}
				return err
			},
		},
		fsm.State(hashIsSet): {
			func(e fsm.Event, _ fsm.State) error {
				var err error
				switch Event(e) {
				case sethash:
					// record the algorithm and hash
					var n uint64
					n, err = strconv.ParseUint(string(assuan.data[0]), 10, 8)
					if err != nil {
						return fmt.Errorf("couldn't parse uint %s: %v", assuan.data[0], err)
					}
					var ok bool
					if assuan.hashAlgo, ok = openpgp.HashIdToHash(uint8(n)); !ok {
						return fmt.Errorf("invalid hash algorithm value: %x", n)
					}
					hash, err = hexDecode(assuan.data[1:]...)
					if err != nil {
						return fmt.Errorf("couldn't decode hash: %v", err)
					}
					assuan.hash = hash[0]
					_, err = io.WriteString(rw, "OK\n")
				case pksign:
					signature, err = assuan.sign()
					if err != nil {
						return fmt.Errorf("couldn't sign: %v", err)
					}
					_, err = rw.Write(signature)
					if err != nil {
						return fmt.Errorf("couldn't write signature: %v", err)
					}
					_, err = io.WriteString(rw, "\n")
					if err != nil {
						return fmt.Errorf("couldn't write newline: %v", err)
					}
					_, err = io.WriteString(rw, "OK\n")
				case keyinfo:
					err = doKeyinfo(rw, assuan.data, ks)
				default:
					return fmt.Errorf("unknown event: %v", Event(e))
				}
				return err
			},
		},
		fsm.State(decryptingKeyIsSet): {
			func(e fsm.Event, _ fsm.State) error {
				var err error
				switch Event(e) {
				case setkey:
					// SETKEY has a single argument: a keygrip indicating the key which
					// will be used for subsequent decrypting operations
					keygrips, err = hexDecode(assuan.data...)
					if err != nil {
						return fmt.Errorf("couldn't decode keygrips: %v", err)
					}
					for _, k := range ks {
						assuan.decrypter, err = k.GetDecrypter(keygrips[0])
						if err == nil {
							break
						}
					}
					if err != nil {
						_, _ = io.WriteString(rw, "ERR 1 couldn't get key for keygrip\n")
						log.Warn("couldn't get key for keygrip", zap.Error(err))
						return nil // this is not a fatal error
					}
					_, err = io.WriteString(rw, "OK\n")
				case setkeydesc:
					// ignore this event since we don't currently use the client's
					// description in the prompt
					_, err = io.WriteString(rw, "OK\n")
				default:
					return fmt.Errorf("unknown event: %v", Event(e))
				}
				return err
			},
		},
		fsm.State(waitingForCiphertext): {
			func(e fsm.Event, _ fsm.State) error {
				var err error
				switch Event(e) {
				case pkdecrypt:
					// once we receive PKDECRYPT we enter a "reversed" state where the
					// agent drives the client by sending commands.
					// ask for ciphertext
					_, err = io.WriteString(rw,
						"S INQUIRE_MAXLEN 4096\nINQUIRE CIPHERTEXT\n")
					if err != nil {
						return err
					}
					var chunk []byte
					var chunks [][]byte
					scanner := bufio.NewScanner(assuan.reader)
					for scanner.Scan() {
						chunk = scanner.Bytes()
						if bytes.Equal([]byte("END"), chunk) {
							break // end of ciphertext
						}
						chunks = append(chunks, chunk)
					}
					if len(chunks) < 1 {
						return fmt.Errorf("invalid ciphertext format")
					}
					var plaintext, ciphertext []byte
					ciphertext = bytes.Join(chunks, []byte("\n"))
					// start notify timer
					cancel := assuan.notify.Touch()
					defer cancel()
					plaintext, err = assuan.decrypter.Decrypt(nil, ciphertext, nil)
					if err != nil {
						return fmt.Errorf("couldn't decrypt: %v", err)
					}
					_, err = rw.Write(plaintext)
				case setkeydesc:
					// ignore this event since we don't currently use the client's
					// description in the prompt
					_, err = io.WriteString(rw, "OK\n")
				case havekey:
					// gpg skips the RESET command occasionally so we have to emulate it.
					assuan.reset()
					// now jump straight to havekey
					if err = assuan.havekey(rw, ks); err != nil {
						return err
					}
					_, err = io.WriteString(rw, "OK\n")
				default:
					return fmt.Errorf("unknown event: %v", Event(e))
				}
				return err
			},
		},
	}
	return &assuan
}

func (assuan *Assuan) reset() {
	assuan.signer = nil
	assuan.decrypter = nil
	assuan.hashAlgo = 0
	assuan.hash = []byte{}
}

func (assuan *Assuan) havekey(rw io.ReadWriter, ks []KeyService) error {
	var err error
	var keyFound bool
	var keygrips [][]byte
	// HAVEKEY arguments are either:
	// * a list of keygrips; or
	// * --list=1000
	// if _any_ key is available, we return OK, otherwise No_Secret_Key.
	// handle --list
	if bytes.HasPrefix(assuan.data[0], []byte("--list")) {
		var grips []byte
		grips, err = allKeygrips(ks)
		if err != nil {
			_, _ = io.WriteString(rw, "ERR 1 couldn't list keygrips\n")
			return err
		}
		// apply libgcrypt encoding
		_, err = io.WriteString(rw, fmt.Sprintf("D %s\nOK\n",
			PercentEncodeSExp(grips)))
		return err
	}
	// handle list of keygrips
	keygrips, err = hexDecode(assuan.data...)
	if err != nil {
		return fmt.Errorf("couldn't decode keygrips: %v", err)
	}
	keyFound, _, err = haveKey(ks, keygrips)
	if err != nil {
		_, _ = io.WriteString(rw, "ERR 1 couldn't check for keygrip\n")
		return err
	}
	if keyFound {
		_, err = io.WriteString(rw, "OK\n")
	} else {
		_, err = io.WriteString(rw, "No_Secret_Key\n")
	}
	return err
}

// doKeyinfo checks for key availability by keygrip, writing the result to rw.
func doKeyinfo(rw io.ReadWriter, data [][]byte, ks []KeyService) error {
	// KEYINFO arguments are a list of keygrips
	// if _any_ key is available, we return info, otherwise
	// No_Secret_Key.
	keygrips, err := hexDecode(data...)
	if err != nil {
		return fmt.Errorf("couldn't decode keygrips: %v", err)
	}
	keyFound, keygrip, err := haveKey(ks, keygrips)
	if err != nil {
		_, _ = io.WriteString(rw, "ERR 1 couldn't match keygrip\n")
		return fmt.Errorf("couldn't match keygrip: %v", err)
	}
	if keyFound {
		_, err = io.WriteString(rw,
			fmt.Sprintf("S KEYINFO %s D - - - - - - -\nOK\n",
				strings.ToUpper(hex.EncodeToString(keygrip))))
		return err
	}
	_, err = io.WriteString(rw, "No_Secret_Key\n")
	return err
}

// haveKey returns true if any of the keygrips refer to keys known locally, and
// false otherwise.
// It takes keygrips in raw byte format, so keygrip in hex-encoded form must
// first be decoded before being passed to this function. It returns the
// keygrip found.
func haveKey(ks []KeyService, keygrips [][]byte) (bool, []byte, error) {
	var keyFound bool
	var keygrip []byte
	var err error
	for _, k := range ks {
		keyFound, keygrip, err = k.HaveKey(keygrips)
		if err != nil {
			return false, nil, fmt.Errorf("couldn't check %s keygrips: %v", k.Name(), err)
		}
		if keyFound {
			return true, keygrip, nil
		}
	}
	return false, nil, nil
}

// allKeygrips returns all keygrips available for any of the given keyservices,
// concatenated into a single byte slice.
func allKeygrips(ks []KeyService) ([]byte, error) {
	var grips []byte
	for _, k := range ks {
		kgs, err := k.Keygrips()
		if err != nil {
			return nil, fmt.Errorf("couldn't get keygrips for %s: %v", k.Name(), err)
		}
		for _, kg := range kgs {
			grips = append(grips, kg...)
		}
	}
	return grips, nil
}

// hexDecode take a list of hex-encoded bytestring values and converts them to
// their raw byte representation.
func hexDecode(data ...[]byte) ([][]byte, error) {
	var decoded [][]byte
	for _, d := range data {
		dst := make([]byte, hex.DecodedLen(len(d)))
		_, err := hex.Decode(dst, d)
		if err != nil {
			return nil, err
		}
		decoded = append(decoded, dst)
	}
	return decoded, nil
}
