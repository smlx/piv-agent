package key

import (
	"fmt"

	"github.com/gliderlabs/ssh"
	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/openpgp/packet"
)

// Sign represents a signing key on a security key / hardware token.
type Sign struct {
	PubSSH      ssh.PublicKey
	PubPGP      *packet.PublicKey
	Slot        piv.Slot
	TouchPolicy piv.TouchPolicy
}

// Security represents a hardware security key.
type Security struct {
	Card        string
	Key         *piv.YubiKey
	Serial      uint32
	SigningKeys []Sign
}

// SlotSpec represents a combination of slot and touch policy on the token.
type SlotSpec struct {
	Slot        piv.Slot
	TouchPolicy piv.TouchPolicy
}

// SignSlots represents the slot specifications for signing operations.
// https://developers.yubico.com/PIV/Introduction/Certificate_slots.html
var SignSlots = []SlotSpec{
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
var EncryptSlots = []SlotSpec{
	// Slot 9d: Key Management
	// This certificate and its associated private key is used for encryption for
	// the purpose of confidentiality. This slot is used for things like
	// encrypting e-mails or files. The end user PIN is required to perform any
	// private key operations. Once the PIN has been provided successfully,
	// multiple private key operations may be performed without additional
	// cardholder consent.
	{piv.SlotKeyManagement, piv.TouchPolicyCached},
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
