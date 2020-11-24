package gopass

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative pb/crypto.proto

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/aead/ecdh"
	"github.com/smlx/piv-agent/internal/gopass/pb"
	"github.com/smlx/piv-agent/internal/token"
	"github.com/vmihailenco/msgpack/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ECDSAPubKeyParams contains the parameters for an ECDSA public key.
type ECDSAPubKeyParams struct {
	X *big.Int
	Y *big.Int
}

// Secret contains the secret with all required parameters for decryption.
type Secret struct {
	Ciphertext []byte
	Nonce      [24]byte
	KeyType    string
	PubKey     []byte
}

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
		ids.Identities = append(ids.Identities, bytes.TrimSpace(ssh.MarshalAuthorizedKey(sks.PubKey)))
	}
	return &ids, nil
}

// Crypto

// Encrypt will encrypt the given content for the recipients.
func (c *GPCrypto) Encrypt(ctx context.Context, a *pb.EncryptArgs) (*pb.Ciphertext, error) {
	ct := map[string]Secret{}
	for _, recipient := range a.Recipients {
		// Unmarshal the public key
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(recipient)
		if err != nil {
			return nil, fmt.Errorf("invalid recipient: %w", err)
		}
		// Figure out what kind of key it is
		// Generate an ephemeral keypair of the correct type
		// Perform ECDH to generate a shared secret
		salt := make([]byte, 20)
		_, err = rand.Read(salt)
		if err != nil {
			return nil, fmt.Errorf("couldn't read salt: %w", err)
		}
		var secretKey [32]byte
		es := Secret{
			KeyType: pubKey.Type(),
		}
		switch pubKey.Type() {
		case "ecdsa-sha2-nistp256":
			p256 := ecdh.Generic(elliptic.P256())
			if err = p256.Check(pubKey); err != nil {
				return nil, fmt.Errorf("public key not on nistp256 curve: %w", err)
			}
			privEphemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("couldn't generate ecdsa key: %w", err)
			}
			es.PubKey, err = msgpack.Marshal(&ECDSAPubKeyParams{
				X: privEphemeral.PublicKey.X,
				Y: privEphemeral.PublicKey.Y,
			})
			if err != nil {
				return nil, fmt.Errorf("couldn't marshal ecdsa pub key: %w", err)
			}
			// params from https://blog.filippo.io/the-scrypt-parameters/
			// Use scrypt as a KDF from the shared secret
			keyBytes, err := scrypt.Key(
				p256.ComputeSecret(privEphemeral, pubKey), salt, 1<<20, 8, 1, 32)
			if err != nil {
				return nil, fmt.Errorf("scrypt KDF error: %w", err)
			}
			copy(secretKey[:], keyBytes)
		case "ssh-ed25519":
			c25519 := ecdh.X25519()
			if err = c25519.Check(pubKey); err != nil {
				return nil, fmt.Errorf("public key not on ed25519 curve: %w", err)
			}
			pubEphemeral, privEphemeral, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("couldn't generate ed25519 key: %w", err)
			}
			es.PubKey = pubEphemeral
			keyBytes, err := scrypt.Key(
				c25519.ComputeSecret(privEphemeral, pubKey), salt, 1<<20, 8, 1, 32)
			if err != nil {
				return nil, fmt.Errorf("scrypt KDF error: %w", err)
			}
			copy(secretKey[:], keyBytes)
		default:
			return nil, fmt.Errorf("invalid recipient keytype: %v", pubKey.Type())
		}
		// Generate a nonce
		if _, err := io.ReadFull(rand.Reader, es.Nonce[:]); err != nil {
			return nil, fmt.Errorf("couldn't generate nonce: %w", err)
		}
		// generate a nacl.secretbox
		es.Ciphertext = secretbox.Seal(es.Nonce[:], a.Plaintext, &es.Nonce, &secretKey)
		// TODO: figure out the correct data structure for this.
		// []byte key is not allowed, string is. could convert but messy.
		// maybe a list is better than a map?
		ct[recipient] = es
	}
	// marshal to yaml
	// return
	return ct, nil
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
