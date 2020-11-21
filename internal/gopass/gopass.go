package gopass

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative pb/crypto.proto

import (
	"context"

	"github.com/smlx/piv-agent/internal/gopass/pb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// GPCrypto implements the gopass backend crypto interface defined in
// https://github.com/gopasspw/gopass/blob/master/internal/backend/crypto.go
type GPCrypto struct {
	pb.UnimplementedCryptoServer
}

// Keyring

// ListIdentities returns a list of available keys.
func (c *GPCrypto) ListIdentities(ctx context.Context, _ *emptypb.Empty) (*pb.Identities, error) {
	return nil, nil
}

// GenerateIdentity will create a new keypair in batch mode.
func (c *GPCrypto) GenerateIdentity(ctx context.Context, a *pb.Identity) (*emptypb.Empty, error) {
	return nil, nil
}

// Crypto

// Encrypt will encrypt the given content for the recipients.
func (c *GPCrypto) Encrypt(ctx context.Context, a *pb.EncryptArgs) (*pb.Ciphertext, error) {
	return nil, nil
}

// Decrypt will try to decrypt the given data.
func (c *GPCrypto) Decrypt(ctx context.Context, a *pb.DecryptArgs) (*pb.Cleartext, error) {
	return nil, nil
}

// Name returns "piv-agent".
func (c *GPCrypto) Name(ctx context.Context, _ *emptypb.Empty) (*pb.ServerName, error) {
	return nil, nil
}

// Version will return piv-agent version information.
func (c *GPCrypto) Version(ctx context.Context, _ *emptypb.Empty) (*pb.ServerVersion, error) {
	return nil, nil
}

// Initialized always returns nil.
func (c *GPCrypto) Initialized(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return nil, nil
}

// Ext returns the file extension used by this backend: "piv".
func (c *GPCrypto) Ext(ctx context.Context, _ *emptypb.Empty) (*pb.Extension, error) {
	return nil, nil
}

// IDFile returns the name of the recipients file used by this backend: ".piv-id".
func (c *GPCrypto) IDFile(ctx context.Context, _ *emptypb.Empty) (*pb.IDFileName, error) {
	return nil, nil
}
