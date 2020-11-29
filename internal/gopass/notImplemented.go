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
func (c *Crypto) GenerateIdentity(ctx context.Context, name, email, passphrase string) error {
	return ErrNotImplemented
}

// ImportPublicKey is not implemented.
func (c *Crypto) ImportPublicKey(ctx context.Context, key []byte) error {
	return ErrNotImplemented
}

// ExportPublicKey is not implemented.
func (c *Crypto) ExportPublicKey(ctx context.Context, id string) ([]byte, error) {
	return nil, ErrNotImplemented
}

// ListRecipients is not implemented.
func (c *Crypto) ListRecipients(ctx context.Context) ([]string, error) {
	return nil, ErrNotImplemented
}

// FindRecipients is not implemented.
func (c *Crypto) FindRecipients(ctx context.Context, needles ...string) ([]string, error) {
	return nil, ErrNotImplemented
}

// FindIdentities is not implemented.
func (c *Crypto) FindIdentities(ctx context.Context, needles ...string) ([]string, error) {
	return nil, ErrNotImplemented
}

// Fingerprint is not implemented.
func (c *Crypto) Fingerprint(ctx context.Context, id string) string {
	return id
}

// FormatKey is not implemented.
func (c *Crypto) FormatKey(ctx context.Context, id, tpl string) string {
	return id
}

// ReadNamesFromKey is not implemented.
func (c *Crypto) ReadNamesFromKey(ctx context.Context, buf []byte) ([]string, error) {
	return nil, ErrNotImplemented
}

// Crypto

// RecipientIDs is not implemented.
func (c *Crypto) RecipientIDs(ctx context.Context, ciphertext []byte) ([]string, error) {
	return nil, ErrNotImplemented
}
