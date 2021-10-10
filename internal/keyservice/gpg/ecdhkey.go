package gpg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io"
	"regexp"

	"github.com/smlx/piv-agent/internal/assuan"
)

var ciphertextECDH = regexp.MustCompile(
	`^D \(7:enc-val\(4:ecdh\(1:s\d+:.+\)\(1:e(\d+):(.+)\)\)\)$`)

// ECDHKey implements ECDH using an underlying ECDSA key.
type ECDHKey struct {
	ecdsa *ecdsa.PrivateKey
}

// Decrypt performs ECDH as per gpg-agent.
func (k *ECDHKey) Decrypt(_ io.Reader, sexp []byte,
	_ crypto.DecrypterOpts) ([]byte, error) {
	// parse out the ephemeral public key
	matches := ciphertextECDH.FindAllSubmatch(sexp, -1)
	ciphertext := matches[0][2]
	// undo the buggy encoding sent by gpg
	ciphertext = assuan.PercentDecodeSExp(ciphertext)
	// unmarshal the ephemeral key
	ephPubX, ephPubY := elliptic.Unmarshal(elliptic.P256(), ciphertext)
	if ephPubX == nil {
		return nil, fmt.Errorf("couldn't unmarshal ephemeral key")
	}
	// perform the scalar mult
	sharedX, sharedY := k.ecdsa.ScalarMult(ephPubX, ephPubY, k.ecdsa.D.Bytes())
	// marshal, encode, and return the result
	shared := elliptic.Marshal(elliptic.P256(), sharedX, sharedY)
	sharedLen := len(shared)
	shared = assuan.PercentEncodeSExp(shared)
	return []byte(fmt.Sprintf("D (5:value%d:%s)\nOK\n", sharedLen, shared)), nil
}

// Public implements the other required method of the crypto.Decrypter and
// crypto.Signer interfaces.
func (k *ECDHKey) Public() crypto.PublicKey {
	return k.ecdsa.Public()
}
