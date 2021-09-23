package assuan

//go:generate mockgen -source=assuan.go -destination=../mock/mock_assuan.go -package=mock

import (
	"bufio"
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/smlx/fsm"
	"go.uber.org/zap"
	"golang.org/x/crypto/openpgp/s2k"
)

// The KeyService interface provides functions used by the Assuan FSM.
type KeyService interface {
	Name() string
	HaveKey([][]byte) (bool, []byte, error)
	GetSigner([]byte) (crypto.Signer, error)
	GetDecrypter([]byte) (crypto.Decrypter, error)
}

var ciphertextRegex = regexp.MustCompile(
	`^D \(7:enc-val\(3:rsa\(1:a(\d+):(.+)\)\)\)$`)

// New initialises a new gpg-agent server assuan FSM.
// It returns a *fsm.Machine configured in the ready state.
func New(rw io.ReadWriter, log *zap.Logger, ks ...KeyService) *Assuan {
	var keyFound bool
	var signature []byte
	var keygrips, hash [][]byte
	assuan := Assuan{
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
					assuan.signer = nil
					assuan.decrypter = nil
					assuan.hashAlgo = 0
					assuan.hash = []byte{}
					_, err = io.WriteString(rw, "OK\n")
				case option:
					// ignore option values - piv-agent doesn't use them
					_, err = io.WriteString(rw, "OK\n")
				case getinfo:
					if bytes.Equal(assuan.data[0], []byte("version")) {
						// masquerade as a compatible gpg-agent
						_, err = io.WriteString(rw, "D 2.2.27\nOK\n")
					} else {
						err = fmt.Errorf("unknown getinfo command: %q", assuan.data[0])
					}
				case havekey:
					// HAVEKEY arguments are a list of keygrips
					// if _any_ key is available, we return OK, otherwise
					// No_Secret_Key.
					keygrips, err = hexDecode(assuan.data...)
					if err != nil {
						return fmt.Errorf("couldn't decode keygrips: %v", err)
					}
					keyFound, _, err = haveKey(ks, keygrips)
					if err != nil {
						_, err = io.WriteString(rw, "ERR 1 couldn't check for keygrip\n")
						return err
					}
					if keyFound {
						_, err = io.WriteString(rw, "OK\n")
					} else {
						_, err = io.WriteString(rw, "No_Secret_Key\n")
					}
				case keyinfo:
					err = doKeyinfo(rw, assuan.data, ks)
				case scd:
					// ignore scdaemon requests
					_, err = io.WriteString(rw, "ERR 100696144 No such device <SCD>\n")
				case readkey:
					// READKEY argument is a keygrip
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
					n, err = strconv.ParseUint(string(assuan.data[0]), 10, 32)
					if err != nil {
						return fmt.Errorf("couldn't parse uint %s: %v", assuan.data[0], err)
					}
					var ok bool
					if assuan.hashAlgo, ok = s2k.HashIdToHash(byte(n)); !ok {
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
					for {
						if !scanner.Scan() {
							break
						}
						chunk = scanner.Bytes()
						if bytes.Equal([]byte("END"), chunk) {
							break // end of ciphertext
						}
						chunks = append(chunks, chunk)
					}
					if len(chunks) < 1 {
						return fmt.Errorf("invalid ciphertext format")
					}
					sexp := bytes.Join(chunks[:], []byte("\n"))
					matches := ciphertextRegex.FindAllSubmatch(sexp, -1)
					var plaintext, ciphertext []byte
					ciphertext = matches[0][2]
					log.Debug("raw ciphertext",
						zap.Binary("sexp", sexp), zap.Binary("ciphertext", ciphertext))
					// undo the buggy encoding sent by gpg
					ciphertext = percentDecodeSExp(ciphertext)
					log.Debug("normalised ciphertext",
						zap.Binary("ciphertext", ciphertext))
					plaintext, err = assuan.decrypter.Decrypt(nil, ciphertext, nil)
					if err != nil {
						return fmt.Errorf("couldn't decrypt: %v", err)
					}
					// gnupg uses the pre-buggy-encoding length in the sexp
					plaintextLen := len(plaintext)
					// apply the buggy encoding as expected by gpg
					plaintext = percentEncodeSExp(plaintext)
					plaintextSexp := fmt.Sprintf("D (5:value%d:%s)\x00\nOK\n",
						plaintextLen, plaintext)
					_, err = io.WriteString(rw, plaintextSexp)
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
	}
	return &assuan
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

// Work around bug(?) in gnupg where some byte sequences are
// percent-encoded in the sexp. Yes, really. NFI what to do if the
// percent-encoded byte sequences themselves are part of the
// ciphertext. Yikes.
//
// These two functions represent over a week of late nights stepping through
// debug builds of libcrypt in gdb :-(

// percentDecodeSExp replaces the percent-encoded byte sequences with their raw
// byte values.
func percentDecodeSExp(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte{0x25, 0x32, 0x35}, []byte{0x25}) // %
	data = bytes.ReplaceAll(data, []byte{0x25, 0x30, 0x41}, []byte{0x0a}) // \n
	data = bytes.ReplaceAll(data, []byte{0x25, 0x30, 0x44}, []byte{0x0d}) // \r
	return data
}

// percentEncodeSExp replaces the raw byte values with their percent-encoded
// byte sequences.
func percentEncodeSExp(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte{0x25}, []byte{0x25, 0x32, 0x35})
	data = bytes.ReplaceAll(data, []byte{0x0a}, []byte{0x25, 0x30, 0x41})
	data = bytes.ReplaceAll(data, []byte{0x0d}, []byte{0x25, 0x30, 0x44})
	return data
}
