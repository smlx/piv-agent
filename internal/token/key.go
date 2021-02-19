package token

import (
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"go.uber.org/zap"
)

// SlotSpec represents a combination of slot and touch policy on the token.
type SlotSpec struct {
	Slot        piv.Slot
	TouchPolicy piv.TouchPolicy
}

// SignSlotSpecs represents the slot specifications for signing operations.
// https://developers.yubico.com/PIV/Introduction/Certificate_slots.html
var SignSlotSpecs = []SlotSpec{
	// Slot 9a: PIV Authentication
	// This certificate and its associated private key is used to authenticate
	// the card and the cardholder. This slot is used for things like system
	// login. The end user PIN is required to perform any private key operations.
	// Once the PIN has been provided successfully, multiple private key
	// operations may be performed without additional cardholder consent.
	{piv.SlotAuthentication, piv.TouchPolicyCached},
	// Slot 9c: Digital Signature
	// This certificate and its associated private key is used for digital
	// signatures for the purpose of document signing, or signing files and
	// executables. The end user PIN is required to perform any private key
	// operations. The PIN must be submitted every time immediately before a sign
	// operation, to ensure cardholder participation for every digital signature
	// generated.
	{piv.SlotSignature, piv.TouchPolicyAlways},
	// Slot 9e: Card Authentication
	// This certificate and its associated private key is used to support
	// additional physical access applications, such as providing physical access
	// to buildings via PIV-enabled door locks. The end user PIN is NOT required
	// to perform private key operations for this slot.
	{piv.SlotCardAuthentication, piv.TouchPolicyNever},
}

// SignSlotSpecs represents the slot specifications for encryption operations.
var EncryptSlotSpecs = []SlotSpec{
	// Slot 9d: Key Management
	// This certificate and its associated private key is used for encryption for
	// the purpose of confidentiality. This slot is used for things like
	// encrypting e-mails or files. The end user PIN is required to perform any
	// private key operations. Once the PIN has been provided successfully,
	// multiple private key operations may be performed without additional
	// cardholder consent.
	{piv.SlotKeyManagement, piv.TouchPolicyCached},
}

// Token represents a security key / hardware token.
type Token struct {
	Card   string
	Key    *piv.YubiKey
	Serial uint32
}

// List returns all security keys available on the system.
func List(log *zap.Logger) ([]Token, error) {
	var all []Token
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
			all = append(all, Token{
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
