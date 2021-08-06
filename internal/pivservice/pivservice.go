package pivservice

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"sync"

	"github.com/smlx/piv-agent/internal/gpg"
	"go.uber.org/zap"
)

// PIVService represents a collection of tokens and slots accessed by the
// Personal Identity Verifaction card interface.
type PIVService struct {
	mu           sync.Mutex
	log          *zap.Logger
	securityKeys []SecurityKey
}

// New constructs a PIV and returns it.
func New(l *zap.Logger) *PIVService {
	return &PIVService{
		log: l,
	}
}

// Name returns the name of the keyservice.
func (p *PIVService) Name() string {
	return "PIV"
}

// HaveKey takes a list of keygrips, and returns a boolean indicating if any of
// the given keygrips were found, the found keygrip, and an error, if any.
func (p *PIVService) HaveKey(keygrips [][]byte) (bool, []byte, error) {
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
func (p *PIVService) GetSigner(keygrip []byte) (crypto.Signer, error) {
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
				cryptoPrivKey, err := sk.PrivateKey(&signingKey)
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
func (p *PIVService) GetDecrypter(keygrip []byte) (crypto.Decrypter, error) {
	// TODO: implement this
	return nil, fmt.Errorf("not implemented")
}
