package piv

import (
	"fmt"
	"log/slog"
	"slices"

	pivgo "github.com/go-piv/piv-go/v2/piv"
	"github.com/smlx/piv-agent/internal/pinentry"
	"github.com/smlx/piv-agent/internal/securitykey"
)

func (p *KeyService) reloadSecurityKeys(cards []string) error {
	// try to clean up and reset state
	for _, k := range p.securityKeys {
		_ = k.Close()
	}
	p.securityKeys = nil
	// load keys from scratch
	for _, card := range cards {
		sk, err := securitykey.New(card, pinentry.New("pinentry"))
		if err != nil {
			p.log.Warn("couldn't get SecurityKey", slog.String("card", card),
				slog.Any("error", err))
			continue
		}
		p.securityKeys = append(p.securityKeys, sk)
	}
	if len(p.securityKeys) == 0 {
		p.log.Warn("no valid security keys found")
	}
	return nil
}

func (p *KeyService) getSecurityKeys() ([]*securitykey.SecurityKey, error) {
	var err error
	// check if the card cache is valid, and reload if not
	cards, err := pivgo.Cards()
	if err != nil {
		return nil, fmt.Errorf("couldn't get cards: %v", err)
	}
	// check the cache size
	reload := len(cards) != len(p.securityKeys)
	if !reload {
		for _, sk := range p.securityKeys {
			// check the cache contents
			if !slices.ContainsFunc(cards, func(card string) bool {
				return card == sk.Card()
			}) {
				reload = true
				break
			}
			// check the keys are healthy
			if _, err = sk.AttestationCertificate(); err != nil {
				p.log.Debug("PIV KeyService: couldn't get AttestationCertificate()",
					slog.Any("error", err))
				reload = true
				break
			}
		}
	}
	if reload || len(p.securityKeys) == 0 {
		if err = p.reloadSecurityKeys(cards); err != nil {
			return nil, fmt.Errorf("couldn't reload security keys: %v", err)
		}
	}
	return p.securityKeys, nil
}

// SecurityKeys returns a slice containing all available security keys.
func (p *KeyService) SecurityKeys() ([]*securitykey.SecurityKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.getSecurityKeys()
}
