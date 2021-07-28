package gpg

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
)

// RSAKey represents a GPG loaded from a keyfile.
// It implements the crypto.Decrypter and crypto.Signer interfaces.
type RSAKey struct {
	rsa *rsa.PrivateKey
}

// Decrypt performs RSA decryption as per gpg-agent.
func (k *RSAKey) Decrypt(_ io.Reader, ciphertext []byte,
	_ crypto.DecrypterOpts) ([]byte, error) {
	c := new(big.Int)
	c.SetBytes(ciphertext)
	// libgcrypt does this, not sure if required
	c.Rem(c, k.rsa.N)
	// perform arithmetic manually
	c.Exp(c, k.rsa.D, k.rsa.N)
	return c.Bytes(), nil
}

// Public implements the crypto.Decrypter interface.
func (k *RSAKey) Public() crypto.PublicKey {
	return k.rsa.Public()
}

// Sign performs RSA signing as per gpg-agent.
func (k *RSAKey) Sign(_ io.Reader, digest []byte,
	_ crypto.SignerOpts) ([]byte, error) {
	// TODO: implement this
	return nil, fmt.Errorf("not implemented")
}
