package gpg

import (
	"crypto"
	"crypto/rsa"
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
	// TODO: libgcrypt does this, not sure if required?
	c.Rem(c, k.rsa.N)
	// perform arithmetic manually
	c.Exp(c, k.rsa.D, k.rsa.N)
	return c.Bytes(), nil
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
