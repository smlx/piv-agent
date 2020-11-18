package gopass

import (
	"context"

	"github.com/blang/semver"
)

// GPCrypto implements the gopass backend crypto interface defined in
// https://github.com/gopasspw/gopass/blob/master/internal/backend/crypto.go
type GPCrypto struct {
}

// Keyring

func (c *GPCrypto) ListIdentities(ctx context.Context) ([]string, error) {
	return nil, nil
}

func (c *GPCrypto) GenerateIdentity(ctx context.Context, name, email, passphrase string) error {
	return nil
}

// Crypto

func (c *GPCrypto) Encrypt(ctx context.Context, plaintext []byte, recipients []string) ([]byte, error) {
	return nil, nil
}
func (c *GPCrypto) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return nil, nil
}

func (c *GPCrypto) Name() string {
	return ""
}
func (c *GPCrypto) Version(context.Context) semver.Version {
	return semver.Version{}
}
func (c *GPCrypto) Initialized(ctx context.Context) error {
	return nil
}
func (c *GPCrypto) Ext() string {
	return ""
}
func (c *GPCrypto) IDFile() string {
	return ""
}
