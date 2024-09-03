package piv

import (
	"crypto"
	"crypto/ecdh"
	"fmt"
	"io"
	"regexp"
	"sync"

	pivgo "github.com/go-piv/piv-go/v2/piv"
	"github.com/smlx/piv-agent/internal/assuan"
)

var ciphertextECDH = regexp.MustCompile(
	`^D \(7:enc-val\(4:ecdh\(1:s\d+:.+\)\(1:e(\d+):(.+)\)\)\)$`)

// ECDHKey implements ECDH using an underlying ECDSA key.
type ECDHKey struct {
	mu *sync.Mutex
	*pivgo.ECDSAPrivateKey
}

// Decrypt performs ECDH as per gpg-agent, and implements the crypto.Decrypter
// interface.
func (k *ECDHKey) Decrypt(_ io.Reader, sexp []byte,
	_ crypto.DecrypterOpts) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	// parse out the ephemeral public key
	matches := ciphertextECDH.FindAllSubmatch(sexp, -1)
	ciphertext := matches[0][2]
	// undo the buggy encoding sent by gpg
	ciphertext = assuan.PercentDecodeSExp(ciphertext)
	// unmarshal the ephemeral key
	ephPub, err := ecdh.P256().NewPublicKey(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("couldn't unmarshal ephemeral key: %v", err)
	}
	// perform scalar multiplication, encode, and return the result
	shared, err := k.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate shared secret: %v", err)
	}
	sharedLen := len(shared)
	shared = assuan.PercentEncodeSExp(shared)
	return []byte(fmt.Sprintf("D (5:value%d:%s)\nOK\n", sharedLen, shared)), nil
}

// Sign wraps the underlying private key Sign operation in a mutex.
func (k *ECDHKey) Sign(rand io.Reader, digest []byte,
	opts crypto.SignerOpts) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.ECDSAPrivateKey.Sign(rand, digest, opts)
}
