package gopass

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative pb/crypto.proto

import (
	"bytes"
	"context"
	"crypto"
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
	"sigs.k8s.io/yaml"
)

// ECDSAPubKeyParams contains the parameters for an ECDSA public key.
type ECDSAPubKeyParams struct {
	X *big.Int
	Y *big.Int
}

// Secret contains the secret with all required parameters for decryption.
type Secret struct {
	Ciphertext []byte
	KeyType    string
	Nonce      [24]byte
	PubKey     []byte
	Recipient  []byte
	Salt       []byte
}

// Crypto implements the gopass backend crypto interface defined in
// https://github.com/gopasspw/gopass/blob/master/internal/backend/crypto.go
type Crypto struct {
	pb.UnimplementedCryptoServer

	agent      Agent
	exitTicker *time.Ticker
	log        *zap.Logger
	version    string
}

// Agent represents a crypto agent.
type Agent interface {
	PublicKeys() ([]ssh.PublicKey, error)
	SharedKey(recipient []byte, peer crypto.PublicKey) ([]byte, error)
}

// NewCrypto constructs a new gopass crypto grpc server.
func NewCrypto(a Agent, et *time.Ticker, log *zap.Logger, version string) *Crypto {
	return &Crypto{
		agent:      a,
		exitTicker: et,
		log:        log,
		version:    version,
	}
}

// Keyring

// ListIdentities returns a list of available keys.
func (c *Crypto) ListIdentities(ctx context.Context, _ *emptypb.Empty) (*pb.Identities, error) {
	securityKeys, err := token.List(c.log)
	if err != nil {
		c.log.Error("couldn't get security keys", zap.Error(err))
		return nil, fmt.Errorf("couldn't get security keys: %w", err)
	}
	sshKeySpecs, err := token.SSHKeySpecs(securityKeys)
	if err != nil {
		c.log.Error("couldn't get SSH public keys", zap.Error(err))
		return nil, fmt.Errorf("couldn't get SSH public keys: %w", err)
	}
	var ids pb.Identities
	for _, sks := range sshKeySpecs {
		ids.Identities = append(ids.Identities, bytes.TrimSpace(ssh.MarshalAuthorizedKey(sks.PublicKey)))
	}
	return &ids, nil
}

// Crypto

// Encrypt will encrypt the given content for the recipients.
func (c *Crypto) Encrypt(ctx context.Context, a *pb.EncryptArgs) (*pb.Ciphertext, error) {
	secretList := []Secret{}
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
			KeyType:   pubKey.Type(),
			Recipient: recipient,
			Salt:      salt,
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
		// assign a nacl.secretbox to es.Ciphertext
		_ = secretbox.Seal(es.Ciphertext, a.Plaintext, &es.Nonce, &secretKey)
		// append encrypted Secret to the list
		secretList = append(secretList, es)
	}
	// marshal to yaml
	y, err := yaml.Marshal(secretList)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal yaml: %w", err)
	}
	// return yaml ciphertext
	return &pb.Ciphertext{
		Ciphertext: y,
	}, nil
}

// Decrypt will try to decrypt the given data.
func (c *Crypto) Decrypt(
	ctx context.Context, a *pb.DecryptArgs) (*pb.Cleartext, error) {
	// unmarshal YAML to secretList
	var secretList []Secret
	if err := yaml.Unmarshal(a.Ciphertext, secretList); err != nil {
		return nil, fmt.Errorf("couldn't unmarshal secretList: %w", err)
	}
	// get the available public keys
	pubKeys, err := c.agent.PublicKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get public keys from agent: %w", err)
	}

	// check each recipient in the secretList for a match
	for _, pubKey := range pubKeys {
		for _, s := range secretList {
			if bytes.Equal(s.Recipient,
				bytes.TrimSpace(ssh.MarshalAuthorizedKey(pubKey))) {
				// unmarshal the peer to get the public key
				pubKeyParams := ECDSAPubKeyParams{}
				if err = msgpack.Unmarshal(s.PubKey, &pubKeyParams); err != nil {
					return nil, fmt.Errorf("couldn't unmarshal peer pubkey params: %w", err)
				}
				ecdsaPubKey := ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     pubKeyParams.X,
					Y:     pubKeyParams.Y,
				}
				sharedKey, err := c.agent.SharedKey(s.Recipient, ecdsaPubKey)
				if err != nil {
					return nil, fmt.Errorf("agent couldn't compute shared key: %w", err)
				}
				// then decrypt the matching secret
				keyBytes, err := scrypt.Key(sharedKey, s.Salt, 1<<20, 8, 1, 32)
				if err != nil {
					return nil, fmt.Errorf("scrypt KDF error: %w", err)
				}
				var secretKey [32]byte
				copy(secretKey[:], keyBytes)
				resp := pb.Cleartext{}
				_, ok := secretbox.Open(resp.Cleartext, s.Ciphertext, &s.Nonce, &secretKey)
				if !ok {
					return nil, fmt.Errorf("couldn't decrypt secretbox")
				}
				return &resp, nil
			}
		}
	}
	return nil, fmt.Errorf("no key matching a recipient available")
}

// Name returns "piv-agent".
func (c *Crypto) Name(ctx context.Context, _ *emptypb.Empty) (*pb.ServerName, error) {
	return &pb.ServerName{Name: "piv-agent"}, nil
}

// Version will return piv-agent version information.
func (c *Crypto) Version(ctx context.Context, _ *emptypb.Empty) (*pb.ServerVersion, error) {
	return &pb.ServerVersion{Version: c.version}, nil
}

// Initialized always returns nil.
func (c *Crypto) Initialized(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// Ext returns the file extension used by this backend: "piv".
func (c *Crypto) Ext(ctx context.Context, _ *emptypb.Empty) (*pb.Extension, error) {
	return &pb.Extension{Ext: "pa"}, nil
}

// IDFile returns the name of the recipients file used by this backend: ".piv-id".
func (c *Crypto) IDFile(ctx context.Context, _ *emptypb.Empty) (*pb.IDFileName, error) {
	return &pb.IDFileName{Name: ".piv-agent-id"}, nil
}
