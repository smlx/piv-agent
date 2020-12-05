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
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/smlx/piv-agent/internal/gopass/pb"
	"github.com/smlx/piv-agent/internal/token"
	"go.uber.org/zap"
	"golang.org/x/crypto/curve25519"
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
	Nonce      []byte
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
	SharedKey(recipient, peer crypto.PublicKey) ([]byte, error)
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
	var secretList []Secret
	for _, recipient := range a.Recipients {
		// Unmarshal the public key
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(recipient)
		if err != nil {
			return nil, fmt.Errorf("invalid recipient: %w", err)
		}
		// Generate a salt
		salt := make([]byte, 20)
		_, err = rand.Read(salt)
		if err != nil {
			return nil, fmt.Errorf("couldn't read salt: %w", err)
		}
		// secretKey is the shared secret used to seal the secretbox
		var secretKey [32]byte
		es := Secret{
			KeyType: pubKey.Type(),
			Salt:    salt,
		}
		// figure out what kind of key it is
		cPubKey, ok := pubKey.(ssh.CryptoPublicKey)
		if !ok {
			return nil, fmt.Errorf("couldn't cast to ssh.CryptoPublicKey")
		}
		// handle each key type
		switch cPubKey.CryptoPublicKey().(type) {
		case *ecdsa.PublicKey:
			ecdsaPubKey, ok := cPubKey.CryptoPublicKey().(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("couldn't cast to *ecdsa.PublicKey")
			}
			curve := elliptic.P256()
			if !curve.IsOnCurve(ecdsaPubKey.X, ecdsaPubKey.Y) {
				return nil, fmt.Errorf("public key not on nistp256 curve: %w", err)
			}
			// recipient is a valid key
			es.Recipient = ssh.MarshalAuthorizedKey(pubKey)
			// Generate an ephemeral key of the correct type
			privEphemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("couldn't generate ecdsa key: %w", err)
			}
			ephSSHPubKey, err := ssh.NewPublicKey(&privEphemeral.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't convert to ssh key type: %w", err)
			}
			es.PubKey = ssh.MarshalAuthorizedKey(ephSSHPubKey)
			// generate shared secret as per
			// https://tools.ietf.org/html/rfc6090#section-4
			sX, _ := curve.ScalarMult(ecdsaPubKey.X, ecdsaPubKey.Y, privEphemeral.D.Bytes())
			c.log.Debug("ECDH shared secret", zap.Binary("secret", sX.Bytes()))
			// Use scrypt as a KDF from the shared secret
			// params from https://blog.filippo.io/the-scrypt-parameters/
			keyBytes, err := scrypt.Key(sX.Bytes(), salt, 1<<20, 8, 1, 32)
			if err != nil {
				return nil, fmt.Errorf("scrypt KDF error: %w", err)
			}
			copy(secretKey[:], keyBytes)
		case ed25519.PublicKey:
			ed25519PubKey, ok := cPubKey.CryptoPublicKey().(ed25519.PublicKey)
			if !ok {
				return nil, fmt.Errorf("couldn't cast to *ed25519.PublicKey")
			}
			pubEphemeral, privEphemeral, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("couldn't generate ed25519 key: %w", err)
			}
			es.PubKey = pubEphemeral
			// generate shared secret
			ss, err := curve25519.X25519(privEphemeral, ed25519PubKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't perform scalar multiplication: %w", err)
			}
			keyBytes, err := scrypt.Key(ss, salt, 1<<20, 8, 1, 32)
			if err != nil {
				return nil, fmt.Errorf("scrypt KDF error: %w", err)
			}
			copy(secretKey[:], keyBytes)
		default:
			return nil, fmt.Errorf("invalid recipient keytype: %v", pubKey.Type())
		}
		// Generate a nonce
		nonce := [24]byte{}
		n, err := io.ReadFull(rand.Reader, nonce[:])
		if err != nil {
			return nil, fmt.Errorf("couldn't generate nonce: %w", err)
		}
		c.log.Debug("copied bytes into nonce", zap.Int("n", n))
		es.Nonce = make([]byte, 24)
		copy(es.Nonce, nonce[:])
		// assign a nacl.secretbox to es.Ciphertext
		c.log.Debug("encrypting",
			zap.String("secretKey", base64.StdEncoding.EncodeToString(secretKey[:])),
			zap.String("nonce", base64.StdEncoding.EncodeToString(es.Nonce)))
		es.Ciphertext = secretbox.Seal(nil, a.Plaintext, &nonce, &secretKey)
		c.log.Debug("wrote ciphertext", zap.Binary("ciphertext", es.Ciphertext))
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
	c.log.Debug("secretList", zap.ByteString("YAML", a.Ciphertext))
	if err := yaml.Unmarshal(a.Ciphertext, &secretList); err != nil {
		return nil, fmt.Errorf("couldn't unmarshal secretList: %w", err)
	}
	// get the available public keys
	pubKeys, err := c.agent.PublicKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get public keys from agent: %w", err)
	}

	c.log.Debug("number of secrets", zap.Int("n", len(secretList)))
	// iterate the secret list
	for _, s := range secretList {
		c.log.Debug("secret", zap.String("recipient", string(s.Recipient)))
		recipientSSHPubKey, _, _, _, err := ssh.ParseAuthorizedKey(s.Recipient)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse ephemeral public key")
		}
		cRecipientSSHPubKey, ok := recipientSSHPubKey.(ssh.CryptoPublicKey)
		if !ok {
			return nil, fmt.Errorf("couldn't cast to ssh.CryptoPublicKey")
		}
		switch cRecipientSSHPubKey.CryptoPublicKey().(type) {
		case *ecdsa.PublicKey:
			recipientPubKey, ok :=
				cRecipientSSHPubKey.CryptoPublicKey().(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("couldn't cast to *ecdsa.PublicKey")
			}
			// check each recipient in the secretList for a match against a local pubkey
			var recipientMatchedPubKey *ecdsa.PublicKey
			for _, pubKey := range pubKeys {
				cPubKey, ok := pubKey.(ssh.CryptoPublicKey)
				if !ok {
					return nil, fmt.Errorf("couldn't cast to ssh.CryptoPublicKey")
				}
				// convert the pubkey to an ecdsa pubkey
				ecdsaPubKey, ok := cPubKey.CryptoPublicKey().(*ecdsa.PublicKey)
				if !ok {
					continue // key type mismatch
				}

				if ecdsaPubKey.Equal(recipientPubKey) {
					recipientMatchedPubKey = recipientPubKey
					break
				}
			}
			if recipientMatchedPubKey == nil {
				continue // no matching pubKey
			}

			// TODO extract this logic into a function
			peerSSHPubKey, _, _, _, err := ssh.ParseAuthorizedKey(s.PubKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't parse peer pub key: %w", err)
			}
			cPeerSSHPubKey, ok := peerSSHPubKey.(ssh.CryptoPublicKey)
			if !ok {
				return nil, fmt.Errorf("couldn't cast to ssh.CryptoPublicKey")
			}

			sharedKey, err := c.agent.SharedKey(recipientMatchedPubKey, cPeerSSHPubKey)
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
			var nonce [24]byte
			copy(nonce[:], s.Nonce)
			resp := pb.Cleartext{}
			c.log.Debug("decrypting",
				zap.String("secretKey", base64.StdEncoding.EncodeToString(secretKey[:])),
				zap.String("nonce", base64.StdEncoding.EncodeToString(s.Nonce)))
			resp.Cleartext, ok = secretbox.Open(nil, s.Ciphertext, &nonce, &secretKey)
			if !ok {
				return nil, fmt.Errorf("couldn't decrypt secretbox")
			}
			return &resp, nil
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
