package gopass

import (
	"context"
	"errors"

	"github.com/smlx/piv-agent/internal/gopass/pb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ErrNotImplemented is returned from any functions which are required to
// implement the gopass Crypto interface but which are not implemented in this
// backend.
var ErrNotImplemented = errors.New("not implemented in piv-agent crypto backend")

// Keyring

func (c *GPCrypto) GenerateIdentity(ctx context.Context, a *pb.Identity) (*emptypb.Empty, error) {
	return nil, nil
}

func (c *GPCrypto) ImportPublicKey(ctx context.Context, key []byte) error {
	return ErrNotImplemented
}
func (c *GPCrypto) ExportPublicKey(ctx context.Context, id string) ([]byte, error) {
	return nil, ErrNotImplemented
}

func (c *GPCrypto) ListRecipients(ctx context.Context) ([]string, error) {
	return nil, ErrNotImplemented
}

func (c *GPCrypto) FindRecipients(ctx context.Context, needles ...string) ([]string, error) {
	return nil, ErrNotImplemented
}
func (c *GPCrypto) FindIdentities(ctx context.Context, needles ...string) ([]string, error) {
	return nil, ErrNotImplemented
}

func (c *GPCrypto) Fingerprint(ctx context.Context, id string) string {
	return id
}
func (c *GPCrypto) FormatKey(ctx context.Context, id, tpl string) string {
	return id
}
func (c *GPCrypto) ReadNamesFromKey(ctx context.Context, buf []byte) ([]string, error) {
	return nil, ErrNotImplemented
}

// Crypto

func (c *GPCrypto) RecipientIDs(ctx context.Context, ciphertext []byte) ([]string, error) {
	return nil, ErrNotImplemented
}
