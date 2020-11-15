package token

import (
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"go.uber.org/zap"
)

// KeySpec represents the specification of a key on the token.
type KeySpec struct {
	Slot        piv.Slot
	TouchPolicy piv.TouchPolicy
}

// AllKeySpecs represents all the key specifications supported by this package.
var AllKeySpecs = []KeySpec{
	{piv.SlotAuthentication, piv.TouchPolicyCached},
	{piv.SlotSignature, piv.TouchPolicyAlways},
	{piv.SlotCardAuthentication, piv.TouchPolicyNever},
}

// SecurityKey represents a security key / hardware token.
type SecurityKey struct {
	Card   string
	Key    *piv.YubiKey
	Serial uint32
}

// List returns all security keys available on the system.
func List(log *zap.Logger) ([]SecurityKey, error) {
	var all []SecurityKey
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("couldn't get smart cards: %w", err)
	}
	var sk *piv.YubiKey
	for _, card := range cards {
		sk, err = piv.Open(card)
		if err != nil {
			log.Debug("couldn't open card", zap.String("card", card), zap.Error(err))
		} else {
			log.Debug("opened card", zap.String("card", card))
			// cache serial
			serial, err := sk.Serial()
			if err != nil {
				log.Warn("couldn't get serial for card",
					zap.String("card", card), zap.Error(err))
				continue
			}
			all = append(all, SecurityKey{
				Card:   card,
				Key:    sk,
				Serial: serial,
			})
		}
	}
	return all, nil
}

// Get returns a security key identified by card string.
func Get(card string) (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("couldn't get smart cards: %w", err)
	}
	if len(cards) > 1 {
		if card == "" {
			return nil, fmt.Errorf("please specify a smart card: %v", cards)
		}
		for i := range cards {
			if cards[i] == card {
				return piv.Open(card)
			}
		}
		return nil, fmt.Errorf("couldn't find specified smart card")
	}
	return piv.Open(cards[0])
}
