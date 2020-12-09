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
	"time"

	"github.com/davecgh/go-spew/spew"
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

// Secret contains the secret with all required parameters for decryption.
type Secret struct {
	Ciphertext []byte
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
func (c *Crypto) Encrypt(ctx context.Context, a *pb.EncryptArgs) (
	*pb.Ciphertext, error) {
	var secretList []Secret
	for _, recipient := range a.Recipients {
		recipientCPK, err := parseSSHAuthorizedKey(recipient)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse recipient public key")
		}
		// Generate a salt
		es := Secret{Salt: make([]byte, 20)}
		spew.Dump(es.Salt)
		_, err = rand.Read(es.Salt)
		if err != nil {
			return nil, fmt.Errorf("couldn't read salt: %w", err)
		}
		spew.Dump(es.Salt)
		// secretKey is the shared secret used to seal the secretbox
		var secretKey [32]byte
		// handle each key type
		switch recipientCPK.(type) {
		case *ecdsa.PublicKey:
			recipientECDSAPubKey := recipientCPK.(*ecdsa.PublicKey)
			curve := elliptic.P256()
			if !curve.IsOnCurve(recipientECDSAPubKey.X, recipientECDSAPubKey.Y) {
				return nil, fmt.Errorf("recipient public key not on nistp256 curve")
			}
			// recipient is a valid key
			rAuthKeyParts := bytes.Fields(recipient)
			rBuf := bytes.Buffer{}
			_, err := fmt.Fprintf(&rBuf, "%s %s", rAuthKeyParts[0], rAuthKeyParts[1])
			if err != nil {
				return nil, fmt.Errorf("couldn't write to buffer: %w", err)
			}
			es.Recipient = rBuf.Bytes()
			//
			// TODO: continue cleanup below...
			//
			// Generate an ephemeral key of the correct type
			privEphemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("couldn't generate ecdsa key: %w", err)
			}
			ephSSHPubKey, err := ssh.NewPublicKey(&privEphemeral.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't convert to ssh key type: %w", err)
			}
			es.PubKey = bytes.TrimSpace(ssh.MarshalAuthorizedKey(ephSSHPubKey))
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
			return nil, fmt.Errorf("invalid recipient key type: %T",
				cPubKey.CryptoPublicKey())
		}
		// Assign a nacl.secretbox to es.Ciphertext.
		// Use a nonce of all zeroes since the ephemeral key is only used once.
		es.Ciphertext = secretbox.Seal(nil, a.Plaintext, &[24]byte{}, &secretKey)
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
	if err := yaml.Unmarshal(a.Ciphertext, &secretList); err != nil {
		return nil, fmt.Errorf("couldn't unmarshal secretList: %w", err)
	}
	// get the available public keys
	localPubKeys, err := c.agent.PublicKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get public keys from agent: %w", err)
	}

	// check each secret for a matching local key
	for _, s := range secretList {
		recipientCPK, err := parseSSHAuthorizedKey(s.Recipient)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse recipient public key")
		}
		switch recipientCPK.(type) {
		case *ecdsa.PublicKey:
			recipientECDSAPubKey := recipientCPK.(*ecdsa.PublicKey)
			// check each recipient for a match against a local pubkey
			var matchedPubKey *ecdsa.PublicKey
			for _, localPubKey := range localPubKeys {
				localCPK, ok := localPubKey.(ssh.CryptoPublicKey)
				if !ok {
					return nil, fmt.Errorf("couldn't cast to ssh.CryptoPublicKey")
				}
				// convert the pubkey to an ecdsa pubkey
				localECDSAPubKey, ok := localCPK.CryptoPublicKey().(*ecdsa.PublicKey)
				if !ok {
					continue // key type mismatch
				}

				if localECDSAPubKey.Equal(recipientECDSAPubKey) {
					matchedPubKey = localECDSAPubKey
					break // success!
				}
			}
			if matchedPubKey == nil {
				continue // no matching pubKey
			}

			peerCPK, err := parseSSHAuthorizedKey(s.PubKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't parse peer public key")
			}

			sharedKey, err := c.agent.SharedKey(matchedPubKey, peerCPK)
			if err != nil {
				return nil, fmt.Errorf("agent couldn't compute shared key: %w", err)
			}
			plaintext, err := decrypt(s.Ciphertext, sharedKey, s.Salt)
			if err != nil {
				return nil, fmt.Errorf("couldn't decrypt secret: %w", err)
			}
			return &pb.Cleartext{Cleartext: plaintext}, nil
		}
	}
	return nil, fmt.Errorf("no local key matching any recipient")
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
