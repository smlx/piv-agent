package pivservice

//go:generate mockgen -source=list.go -destination=../mock/mock_pivservice.go -package=mock

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
	PrivateKey(s *securitykey.SigningKey) (crypto.PrivateKey, error)
	Serial() uint32
	SigningKeys() []securitykey.SigningKey
	StringsGPG(string, string) ([]string, error)
	StringsSSH() []string
}

// SecurityKeys returns a slice containing all available security keys.
func (p *PIVService) SecurityKeys() ([]SecurityKey, error) {
	var all []SecurityKey
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("couldn't get smart cards: %w", err)
	}
	for _, card := range cards {
		sk, err := securitykey.New(card)
		if err != nil {
			p.log.Warn("couldn't get SecurityKey", zap.String("card", card),
				zap.Error(err))
			continue
		}
		all = append(all, sk)
	}
	return all, nil
}
