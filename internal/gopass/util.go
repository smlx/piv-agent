package gopass

import (
	"crypto"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh"
)

func parseSSHAuthorizedKey(aKey []byte) (crypto.PublicKey, error) {
	sshPublicKey, _, _, _, err := ssh.ParseAuthorizedKey(aKey)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse SSH authorized key")
	}
	sshCPK, ok := sshPublicKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot convert ssh.PublicKey to crypto.PublicKey")
	}
	return sshCPK.CryptoPublicKey(), nil
}

func decrypt(ciphertext, sharedKey, salt []byte) ([]byte, error) {
	key, err := scrypt.Key(sharedKey, salt, 1<<20, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("scrypt KDF error: %w", err)
	}
	var secretKey [32]byte
	var ok bool
	copy(secretKey[:], key)
	plaintext, ok := secretbox.Open(nil, ciphertext, &[24]byte{}, &secretKey)
	if !ok {
		return nil, fmt.Errorf("couldn't open secretbox")
	}
	return plaintext, nil
}
