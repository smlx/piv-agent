package gopass

import (
	"context"
	"errors"
)

// ErrNotImplemented is returned from any functions which are required to
// implement the gopass Crypto interface but which are not implemented in this
// backend.
var ErrNotImplemented = errors.New("not implemented in piv-agent crypto backend")

// Keyring

// GenerateIdentity is not implemented.
func (c *GPCrypto) GenerateIdentity(ctx context.Context, name, email, passphrase string) error {
	return ErrNotImplemented
}

// ImportPublicKey is not implemented.
func (c *GPCrypto) ImportPublicKey(ctx context.Context, key []byte) error {
	return ErrNotImplemented
}

// ExportPublicKey is not implemented.
func (c *GPCrypto) ExportPublicKey(ctx context.Context, id string) ([]byte, error) {
	return nil, ErrNotImplemented
}

// ListRecipients is not implemented.
func (c *GPCrypto) ListRecipients(ctx context.Context) ([]string, error) {
	return nil, ErrNotImplemented
}

// FindRecipients is not implemented.
func (c *GPCrypto) FindRecipients(ctx context.Context, needles ...string) ([]string, error) {
	return nil, ErrNotImplemented
}

// FindIdentities is not implemented.
func (c *GPCrypto) FindIdentities(ctx context.Context, needles ...string) ([]string, error) {
	return nil, ErrNotImplemented
}

// Fingerprint is not implemented.
func (c *GPCrypto) Fingerprint(ctx context.Context, id string) string {
	return id
}

// FormatKey is not implemented.
func (c *GPCrypto) FormatKey(ctx context.Context, id, tpl string) string {
	return id
}

// ReadNamesFromKey is not implemented.
func (c *GPCrypto) ReadNamesFromKey(ctx context.Context, buf []byte) ([]string, error) {
	return nil, ErrNotImplemented
}

// Crypto

// RecipientIDs is not implemented.
func (c *GPCrypto) RecipientIDs(ctx context.Context, ciphertext []byte) ([]string, error) {
	return nil, ErrNotImplemented
}
