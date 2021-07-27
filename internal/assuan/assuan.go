package assuan

//go:generate mockgen -source=assuan.go -destination=../mock/mock_assuan.go -package=mock

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/smlx/fsm"
	"github.com/smlx/piv-agent/internal/gpg"
	"github.com/smlx/piv-agent/internal/notify"
	"github.com/smlx/piv-agent/internal/pivservice"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// The PIVService interface provides PIV functions used by the Assuan FSM.
type PIVService interface {
	SecurityKeys() ([]pivservice.SecurityKey, error)
}

// The GPGService interface provides GPG functions used by the Assuan FSM.
type GPGService interface {
	GetKey([]byte) *rsa.PrivateKey
}

// hashFunction maps the code used by assuan to the relevant hash function.
var hashFunction = map[uint64]crypto.Hash{
	8:  crypto.SHA256,
	10: crypto.SHA512,
}

// New initialises a new gpg-agent server assuan FSM.
// It returns a *fsm.Machine configured in the ready state.
func New(w io.Writer, p PIVService, g GPGService) *Assuan {
	var err error
	var keyFound bool
	var keygrip, signature []byte
	var keygrips, hash [][]byte
	assuan := Assuan{
		Machine: fsm.Machine{
			State:       fsm.State(ready),
			Transitions: assuanTransitions,
		},
	}
	assuan.OnEntry = map[fsm.State][]fsm.TransitionFunc{
		fsm.State(connected): {
			func(e fsm.Event, _ fsm.State) error {
				switch Event(e) {
				case connect:
					// acknowledge connection using the format expected by the client
					_, err = io.WriteString(w,
						"OK Pleased to meet you, process 123456789\n")
				case reset:
					assuan.signingPrivKey = nil
					assuan.hashAlgo = 0
					assuan.hash = []byte{}
					_, err = io.WriteString(w, "OK\n")
				case option:
					// ignore option values - piv-agent doesn't use them
					_, err = io.WriteString(w, "OK\n")
				case getinfo:
					if bytes.Equal(assuan.data[0], []byte("version")) {
						// masquerade as a compatible gpg-agent
						_, err = io.WriteString(w, "D 2.2.27\nOK\n")
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
					keyFound, _, err = haveKey(p, g, keygrips)
					if err != nil {
						_, _ = io.WriteString(w, "ERR 1 couldn't check for keygrip\n")
						return fmt.Errorf("couldn't check for keygrip: %v", err)
					}
					if keyFound {
						_, err = io.WriteString(w, "OK\n")
					} else {
						_, err = io.WriteString(w, "No_Secret_Key\n")
					}
				case keyinfo:
					// KEYINFO arguments are a list of keygrips
					// if _any_ key is available, we return OK, otherwise
					// No_Secret_Key.
					keygrips, err = hexDecode(assuan.data...)
					if err != nil {
						return fmt.Errorf("couldn't decode keygrips: %v", err)
					}
					keyFound, keygrip, err = haveKey(p, g, keygrips)
					if err != nil {
						_, _ = io.WriteString(w, "ERR 1 couldn't check for keygrip\n")
						return fmt.Errorf("couldn't check for keygrip: %v", err)
					}
					if keyFound {
						_, err = io.WriteString(w,
							fmt.Sprintf("S KEYINFO %s D - - - P - - -\nOK\n",
								strings.ToUpper(hex.EncodeToString(keygrip))))
					} else {
						_, err = io.WriteString(w, "No_Secret_Key\n")
					}
				default:
					return fmt.Errorf("unknown event: %v", e)
				}
				return err
			},
		},
		fsm.State(keyIsSet): {
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
					assuan.signingPrivKey, err = tokenSigner(p, keygrips[0])
					if err != nil {
						// fall back to keyfiles
						assuan.signingPrivKey, err = keyfileSigner(g, keygrips[0])
					}
					if err != nil {
						_, _ = io.WriteString(w, "ERR 1 couldn't get key from keygrip\n")
						return fmt.Errorf("couldn't get key from keygrip: %v", err)
					}
					_, err = io.WriteString(w, "OK\n")
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
					if assuan.hashAlgo = hashFunction[n]; assuan.hashAlgo == 0 {
						return fmt.Errorf("invalid hash algorithm value: %v", n)
					}
					hash, err = hexDecode(assuan.data[1:]...)
					if err != nil {
						return fmt.Errorf("couldn't decode hash: %v", err)
					}
					assuan.hash = hash[0]
					_, err = io.WriteString(w, "OK\n")
				case pksign:
					signature, err = assuan.sign()
					if err != nil {
						return fmt.Errorf("couldn't sign: %v", err)
					}
					_, err = w.Write(signature)
					if err != nil {
						return fmt.Errorf("couldn't write signature: %v", err)
					}
					_, err = io.WriteString(w, "\n")
					if err != nil {
						return fmt.Errorf("couldn't write newline: %v", err)
					}
					_, err = io.WriteString(w, "OK\n")
				default:
					return fmt.Errorf("unknown event: %v", Event(e))
				}
				return err
			},
		},
	}
	return &assuan
}

// haveKey returns true if any of the keygrips refer to keys held by the local
// PIVService, and false otherwise.
// It takes keygrips in raw byte format, so keygrip in hex-encoded form must
// first be decoded before being passed to this function.
func haveKey(p PIVService, g GPGService, keygrips [][]byte) (bool, []byte, error) {
	securityKeys, err := p.SecurityKeys()
	if err != nil {
		return false, nil, fmt.Errorf("couldn't get security keys: %w", err)
	}
	// check against tokens
	for _, sk := range securityKeys {
		for _, signingKey := range sk.SigningKeys() {
			ecdsaPubKey, ok := signingKey.Public.(*ecdsa.PublicKey)
			if !ok {
				// TODO: handle other key types
				continue
			}
			thisKeygrip, err := gpg.KeygripECDSA(ecdsaPubKey)
			if err != nil {
				return false, nil, fmt.Errorf("couldn't get keygrip: %w", err)
			}
			for _, kg := range keygrips {
				if bytes.Equal(thisKeygrip, kg) {
					return true, thisKeygrip, nil
				}
			}
		}
	}
	// also check against keyfiles
	for _, kg := range keygrips {
		if key := g.GetKey(kg); key != nil {
			return true, kg, nil
		}
	}
	return false, nil, nil
}

// tokenSigner returns the security key associated with the given keygrip.
// If the keygrip doesn't match any known key, err will be non-nil.
// It takes a keygrip in raw byte format, so a keygrip in hex-encoded form must
// first be decoded before being passed to this function.
func tokenSigner(p PIVService, keygrip []byte) (crypto.Signer, error) {
	securityKeys, err := p.SecurityKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get security keys: %w", err)
	}
	for _, k := range securityKeys {
		for _, signingKey := range k.SigningKeys() {
			ecdsaPubKey, ok := signingKey.Public.(*ecdsa.PublicKey)
			if !ok {
				// TODO: handle other key types
				continue
			}
			thisKeygrip, err := gpg.KeygripECDSA(ecdsaPubKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't get keygrip: %w", err)
			}
			if bytes.Equal(thisKeygrip, keygrip) {
				cryptoPrivKey, err := k.PrivateKey(&signingKey)
				if err != nil {
					return nil, fmt.Errorf("couldn't get private key from slot")
				}
				signingPrivKey, ok := cryptoPrivKey.(crypto.Signer)
				if !ok {
					return nil, fmt.Errorf("private key is invalid type")
				}
				return signingPrivKey, nil
			}
		}
	}
	return nil, fmt.Errorf("no matching key")
}

// keyfileSigner returns a crypto.Signer associated with the given keygrip.
// If the keygrip doesn't match any known key, err will be non-nil.
// It takes a keygrip in raw byte format, so a keygrip in hex-encoded form must
// first be decoded before being passed to this function.
// The path is to a secret keys file exported from gpg.
func keyfileSigner(g GPGService, keygrip []byte) (crypto.Signer, error) {
	if key := g.GetKey(keygrip); key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("no matching key")
}

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

// sign performs signing of the specified "hash" data, using the specified
// "hashAlgo" hash algorithm. It then encodes the response into an s-expression
// and returns it as a byte slice.
//
// This function's complexity is due to the fact that while Sign() returns the
// r and s components of the signature ASN1-encoded, gpg expects them to be
// separately s-exp encoded. So we have to decode the ASN1 signature, extract
// the params, and re-encode them into the s-exp. Ugh.
func (a *Assuan) sign() ([]byte, error) {
	cancel := notify.Touch(nil)
	defer cancel()
	signature, err := a.signingPrivKey.Sign(rand.Reader, a.hash, a.hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("couldn't sign: %v", err)
	}
	var sig cryptobyte.String = signature
	var b []byte
	if !sig.ReadASN1Bytes(&b, asn1.SEQUENCE) {
		return nil, fmt.Errorf("couldn't read asn1.SEQUENCE")
	}
	var rawInts cryptobyte.String = b
	var r, s big.Int
	if !rawInts.ReadASN1Integer(&r) {
		return nil, fmt.Errorf("couldn't read r as asn1.Integer")
	}
	if !rawInts.ReadASN1Integer(&s) {
		return nil, fmt.Errorf("couldn't read s as asn1.Integer")
	}
	// encode the params (r, s) into s-exp
	return []byte(fmt.Sprintf(`D (7:sig-val(5:ecdsa(1:r32#%X#)(1:s32#%X#)))`,
		r.Bytes(), s.Bytes())), nil
}
