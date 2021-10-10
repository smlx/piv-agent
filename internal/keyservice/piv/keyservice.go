package piv

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"sync"

	"github.com/smlx/piv-agent/internal/keyservice/gpg"
	"go.uber.org/zap"
)

// KeyService represents a collection of tokens and slots accessed by the
// Personal Identity Verifaction card interface.
type KeyService struct {
	mu           sync.Mutex
	log          *zap.Logger
	securityKeys []SecurityKey
}

// New constructs a PIV and returns it.
func New(l *zap.Logger) *KeyService {
	return &KeyService{
		log: l,
	}
}

// Name returns the name of the keyservice.
func (*KeyService) Name() string {
	return "PIV"
}

// Keygrips returns a single slice of concatenated keygrip byteslices - one for
// each cryptographic key available on the keyservice.
func (p *KeyService) Keygrips() ([][]byte, error) {
	var grips [][]byte
	securityKeys, err := p.SecurityKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get security keys: %w", err)
	}
	for _, sk := range securityKeys {
		for _, signingKey := range sk.SigningKeys() {
			ecdsaPubKey, ok := signingKey.Public.(*ecdsa.PublicKey)
			if !ok {
				// TODO: handle other key types
				continue
			}
			kg, err := gpg.KeygripECDSA(ecdsaPubKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't get keygrip: %w", err)
			}
			grips = append(grips, kg)
		}
	}
	return grips, nil
}

// HaveKey takes a list of keygrips, and returns a boolean indicating if any of
// the given keygrips were found, the found keygrip, and an error, if any.
func (p *KeyService) HaveKey(keygrips [][]byte) (bool, []byte, error) {
	securityKeys, err := p.SecurityKeys()
	if err != nil {
		return false, nil, fmt.Errorf("couldn't get security keys: %w", err)
	}
	for _, sk := range securityKeys {
		for _, signingKey := range sk.SigningKeys() {
			ecdsaPubKey, ok := signingKey.Public.(*ecdsa.PublicKey)
			if !ok {
				// TODO: handle other key types
				continue
			}
			thisKeygrip, err := gpg.KeygripECDSA(ecdsaPubKey)
			if err != nil {
				return false, nil, fmt.Errorf("couldn't get keygrip: %w", err)
			}
			for _, kg := range keygrips {
				if bytes.Equal(thisKeygrip, kg) {
					return true, thisKeygrip, nil
				}
			}
		}
	}
	return false, nil, nil
}

// GetSigner returns a crypto.Signer associated with the given keygrip.
func (p *KeyService) GetSigner(keygrip []byte) (crypto.Signer, error) {
	securityKeys, err := p.SecurityKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get security keys: %w", err)
	}
	for _, sk := range securityKeys {
		for _, signingKey := range sk.SigningKeys() {
			ecdsaPubKey, ok := signingKey.Public.(*ecdsa.PublicKey)
			if !ok {
				// TODO: handle other key types
				continue
			}
			thisKeygrip, err := gpg.KeygripECDSA(ecdsaPubKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't get keygrip: %w", err)
			}
			if bytes.Equal(thisKeygrip, keygrip) {
				cryptoPrivKey, err := sk.PrivateKey(&signingKey.CryptoKey)
				if err != nil {
					return nil, fmt.Errorf("couldn't get private key from slot")
				}
				signingPrivKey, ok := cryptoPrivKey.(crypto.Signer)
				if !ok {
					return nil, fmt.Errorf("private key is invalid type")
				}
				return signingPrivKey, nil
			}
		}
	}
	return nil, fmt.Errorf("couldn't find keygrip")
}

// GetDecrypter returns a crypto.Decrypter associated with the given keygrip.
func (p *KeyService) GetDecrypter(keygrip []byte) (crypto.Decrypter, error) {
	// TODO: implement this
	return nil, fmt.Errorf("not implemented")
}
