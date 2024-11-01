package gpg

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"io"
	"regexp"

	"filippo.io/nistec"
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
	// perform scalar multiplication
	sharedPoint := nistec.NewP256Point()
	_, err := sharedPoint.SetBytes(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("couldn't set point bytes: %v", err)
	}
	_, err = sharedPoint.ScalarMult(sharedPoint, k.ecdsa.D.Bytes())
	if err != nil {
		return nil, fmt.Errorf("couldn't perform scalar mult: %v", err)
	}
	// marshal, encode, and return the result
	shared := sharedPoint.Bytes()
	sharedLen := len(shared)
	shared = assuan.PercentEncodeSExp(shared)
	return []byte(fmt.Sprintf("D (5:value%d:%s)\nOK\n", sharedLen, shared)), nil
}

// Public implements the other required method of the crypto.Decrypter and
// crypto.Signer interfaces.
func (k *ECDHKey) Public() crypto.PublicKey {
	return k.ecdsa.Public()
}
