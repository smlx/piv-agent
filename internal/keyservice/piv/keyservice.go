// Package piv implements the PIV keyservice.
package piv

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"sync"

	pivgo "github.com/go-piv/piv-go/piv"
	"github.com/smlx/piv-agent/internal/keyservice/gpg"
	"github.com/smlx/piv-agent/internal/pinentry"
	"go.uber.org/zap"
)

// KeyService represents a collection of tokens and slots accessed by the
// Personal Identity Verifaction card interface.
type KeyService struct {
	mu           sync.Mutex
	log          *zap.Logger
	pinentry     *pinentry.PINEntry
	securityKeys []SecurityKey
}

// New constructs a PIV and returns it.
func New(l *zap.Logger, pe *pinentry.PINEntry) *KeyService {
	return &KeyService{
		log:      l,
		pinentry: pe,
	}
}

// Name returns the name of the keyservice.
func (*KeyService) Name() string {
	return "PIV"
}

// Keygrips returns a single slice of concatenated keygrip byteslices - one for
// each cryptographic key available on the keyservice.
func (p *KeyService) Keygrips() ([][]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var grips [][]byte
	securityKeys, err := p.getSecurityKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get security keys: %w", err)
	}
	for _, sk := range securityKeys {
		for _, cryptoKey := range sk.CryptoKeys() {
			ecdsaPubKey, ok := cryptoKey.Public.(*ecdsa.PublicKey)
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
	p.mu.Lock()
	defer p.mu.Unlock()
	securityKeys, err := p.getSecurityKeys()
	if err != nil {
		return false, nil, fmt.Errorf("couldn't get security keys: %w", err)
	}
	for _, sk := range securityKeys {
		for _, cryptoKey := range sk.CryptoKeys() {
			ecdsaPubKey, ok := cryptoKey.Public.(*ecdsa.PublicKey)
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

func (p *KeyService) getPrivateKey(keygrip []byte) (crypto.PrivateKey, error) {
	securityKeys, err := p.getSecurityKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get security keys: %w", err)
	}
	for _, sk := range securityKeys {
		for _, cryptoKey := range sk.CryptoKeys() {
			ecdsaPubKey, ok := cryptoKey.Public.(*ecdsa.PublicKey)
			if !ok {
				// TODO: handle other key types
				continue
			}
			thisKeygrip, err := gpg.KeygripECDSA(ecdsaPubKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't get keygrip: %w", err)
			}
			if bytes.Equal(thisKeygrip, keygrip) {
				privKey, err := sk.PrivateKey(&cryptoKey)
				if err != nil {
					return nil, fmt.Errorf("couldn't get private key from slot")
				}
				pivGoPrivKey, ok := privKey.(*pivgo.ECDSAPrivateKey)
				if !ok {
					return nil, fmt.Errorf("unexpected private key type: %T", privKey)
				}
				return &ECDHKey{mu: &p.mu, ECDSAPrivateKey: pivGoPrivKey}, nil
			}
		}
	}
	return nil, fmt.Errorf("couldn't match keygrip")
}

// GetSigner returns a crypto.Signer associated with the given keygrip.
func (p *KeyService) GetSigner(keygrip []byte) (crypto.Signer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	privKey, err := p.getPrivateKey(keygrip)
	if err != nil {
		return nil, fmt.Errorf("couldn't get private key: %v", err)
	}
	signingPrivKey, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is not a signer")
	}
	return signingPrivKey, nil
}

// GetDecrypter returns a crypto.Decrypter associated with the given keygrip.
func (p *KeyService) GetDecrypter(keygrip []byte) (crypto.Decrypter, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	privKey, err := p.getPrivateKey(keygrip)
	if err != nil {
		return nil, fmt.Errorf("couldn't get private key: %v", err)
	}
	decryptingPrivKey, ok := privKey.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("private key is not a decrypter")
	}
	return decryptingPrivKey, nil
}

// CloseAll closes all security keys without checking for errors.
// This should be called to clean up connections to `pcscd`.
func (p *KeyService) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.log.Debug("closing security keys", zap.Int("count", len(p.securityKeys)))
	for _, k := range p.securityKeys {
		if err := k.Close(); err != nil {
			p.log.Debug("couldn't close key", zap.Error(err))
		}
	}
}
