package gpg

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"regexp"

	"github.com/smlx/piv-agent/internal/assuan"
)

var ciphertextRSA = regexp.MustCompile(
	`^D \(7:enc-val\(3:rsa\(1:a(\d+):(.+)\)\)\)$`)

// RSAKey represents a GPG key loaded from a keyfile.
// It implements the crypto.Decrypter and crypto.Signer interfaces.
type RSAKey struct {
	rsa *rsa.PrivateKey
}

// Decrypt performs RSA decryption as per gpg-agent.
// The ciphertext is expected to be in gpg sexp-encoded format, and is returned
// in the same format as expected by the gpg assuan protocol.
//
// Terrible things about this function (not exhaustive):
// * rolling my own crypto
// * possibly makes well-known RSA implementation mistakes(?)
// * RSA in 2021
//
// I'd love to not have to do this, but hey, it's for gnupg compatibility.
// Get in touch if you know how to improve this function.
func (k *RSAKey) Decrypt(_ io.Reader, sexp []byte,
	_ crypto.DecrypterOpts) ([]byte, error) {
	// parse out ciphertext
	matches := ciphertextRSA.FindAllSubmatch(sexp, -1)
	ciphertext := matches[0][2]
	// undo the buggy encoding sent by gpg
	ciphertext = assuan.PercentDecodeSExp(ciphertext)
	// unmarshal ciphertext
	c := new(big.Int)
	c.SetBytes(ciphertext)
	// TODO: libgcrypt does this, not sure if required?
	c.Rem(c, k.rsa.N)
	// perform arithmetic manually
	c.Exp(c, k.rsa.D, k.rsa.N)
	// marshal plaintext
	plaintext := c.Bytes()
	// gnupg uses the pre-buggy-encoding length in the sexp
	plaintextLen := len(plaintext)
	// apply the buggy encoding as expected by gpg
	plaintext = assuan.PercentEncodeSExp(plaintext)
	return []byte(fmt.Sprintf("D (5:value%d:%s)\x00\nOK\n",
		plaintextLen, plaintext)), nil
}

// Public implements the other required method of the crypto.Decrypter and
// crypto.Signer interfaces.
func (k *RSAKey) Public() crypto.PublicKey {
	return k.rsa.Public()
}

// Sign performs RSA signing as per gpg-agent.
func (k *RSAKey) Sign(r io.Reader, digest []byte,
	o crypto.SignerOpts) ([]byte, error) {
	return rsa.SignPKCS1v15(r, k.rsa, o.HashFunc(), digest)
}
