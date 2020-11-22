package gopass

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative pb/crypto.proto

import (
	"context"
	"fmt"
	"time"

	"github.com/smlx/piv-agent/internal/gopass/pb"
	"github.com/smlx/piv-agent/internal/token"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/emptypb"
)

// GPCrypto implements the gopass backend crypto interface defined in
// https://github.com/gopasspw/gopass/blob/master/internal/backend/crypto.go
type GPCrypto struct {
	pb.UnimplementedCryptoServer

	exitTicker *time.Ticker
	log        *zap.Logger
}

// NewCrypto constructs a new gopass crypto grpc server.
func NewCrypto(et *time.Ticker, log *zap.Logger) *GPCrypto {
	return &GPCrypto{
		exitTicker: et,
		log:        log,
	}
}

// Keyring

// ListIdentities returns a list of available keys.
func (c *GPCrypto) ListIdentities(ctx context.Context, _ *emptypb.Empty) (*pb.Identities, error) {
	sks, err := token.List(c.log)
	if err != nil {
		c.log.Error("couldn't get security keys", zap.Error(err))
		return nil, fmt.Errorf("couldn't get security keys: %w", err)
	}
	sshKeySpecs, err := token.SSHKeySpecs(sks)
	if err != nil {
		c.log.Error("couldn't get SSH public keys", zap.Error(err))
		return nil, fmt.Errorf("couldn't get SSH public keys: %w", err)
	}
	var ids pb.Identities
	for _, sks := range sshKeySpecs {
		ids.Identities = append(ids.Identities, string(ssh.FingerprintSHA256(sks.PubKey)))
	}
	return &ids, nil
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
