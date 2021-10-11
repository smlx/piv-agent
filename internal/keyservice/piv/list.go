package piv

//go:generate mockgen -source=list.go -destination=../../mock/mock_pivservice.go -package=mock

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"github.com/smlx/piv-agent/internal/securitykey"
	"go.uber.org/zap"
)

// SecurityKey is a simple interface for security keys allowing abstraction
// over the securitykey implementation, and allowing generation of mocks for
// testing.
type SecurityKey interface {
	AttestationCertificate() (*x509.Certificate, error)
	Card() string
	Close() error
	Comment(*securitykey.SlotSpec) string
	PrivateKey(*securitykey.CryptoKey) (crypto.PrivateKey, error)
	SigningKeys() []securitykey.SigningKey
	CryptoKeys() []securitykey.CryptoKey
	StringsGPG(string, string) ([]string, error)
	StringsSSH() []string
}

func (p *KeyService) reloadSecurityKeys() error {
	// try to clean up and reset state
	for _, k := range p.securityKeys {
		_ = k.Close()
	}
	p.securityKeys = nil
	// open cards and load keys from scratch
	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("couldn't get cards: %v", err)
	}
	for _, card := range cards {
		sk, err := securitykey.New(card)
		if err != nil {
			p.log.Warn("couldn't get SecurityKey", zap.String("card", card),
				zap.Error(err))
			continue
		}
		p.securityKeys = append(p.securityKeys, sk)
	}
	if len(p.securityKeys) == 0 {
		p.log.Warn("no valid security keys found")
	}
	return nil
}

// SecurityKeys returns a slice containing all available security keys.
func (p *KeyService) SecurityKeys() ([]SecurityKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var err error
	// check if any securityKeys are cached, and if not then cache them
	if len(p.securityKeys) == 0 {
		if err = p.reloadSecurityKeys(); err != nil {
			return nil, fmt.Errorf("couldn't reload security keys: %v", err)
		}
	}
	// check they are healthy, and reload if not
	for _, k := range p.securityKeys {
		if _, err = k.AttestationCertificate(); err != nil {
			if err = p.reloadSecurityKeys(); err != nil {
				return nil, fmt.Errorf("couldn't reload security keys: %v", err)
			}
			break
		}
	}
	return p.securityKeys, nil
}
