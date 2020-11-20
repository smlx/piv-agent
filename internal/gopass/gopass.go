package gopass

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative pb/crypto.proto

import (
	"context"

	"github.com/blang/semver"
	"github.com/smlx/piv-agent/internal/gopass/pb"
)

// GPCrypto implements the gopass backend crypto interface defined in
// https://github.com/gopasspw/gopass/blob/master/internal/backend/crypto.go
type GPCrypto struct {
	pb.CryptoService // returns unimplemented
}

// Keyring

// ListIdentities returns a list of available keys.
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
