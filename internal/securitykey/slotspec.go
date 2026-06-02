package securitykey

import (
	"fmt"

	pivgo "github.com/go-piv/piv-go/v2/piv"
)

// SlotSpec represents a combination of slot and touch policy on the token.
type SlotSpec struct {
	Slot        pivgo.Slot
	TouchPolicy pivgo.TouchPolicy
}

// defaultSignSlots represents the default slot specifications for signing
// operations.
// See https://developers.yubico.com/PIV/Introduction/Certificate_slots.html
var defaultSignSlots = map[string]SlotSpec{
	// Slot 9a: PIV Authentication
	// This certificate and its associated private key is used to authenticate
	// the card and the cardholder. This slot is used for things like system
	// login. The end user PIN is required to perform any private key operations.
	// Once the PIN has been provided successfully, multiple private key
	// operations may be performed without additional cardholder consent.
	"cached": {pivgo.SlotAuthentication, pivgo.TouchPolicyCached},
	// Slot 9c: Digital Signature
	// This certificate and its associated private key is used for digital
	// signatures for the purpose of document signing, or signing files and
	// executables. The end user PIN is required to perform any private key
	// operations. The PIN must be submitted every time immediately before a sign
	// operation, to ensure cardholder participation for every digital signature
	// generated.
	"always": {pivgo.SlotSignature, pivgo.TouchPolicyAlways},
	// Slot 9e: Card Authentication
	// This certificate and its associated private key is used to support
	// additional physical access applications, such as providing physical access
	// to buildings via PIV-enabled door locks. The end user PIN is NOT required
	// to perform private key operations for this slot.
	"never": {pivgo.SlotCardAuthentication, pivgo.TouchPolicyNever},
}

// SigningSlotSpec returns the slot specification for a given touch policy.
func SigningSlotSpec(policy string) (SlotSpec, error) {
	if s, ok := defaultSignSlots[policy]; ok {
		return s, nil
	}
	return SlotSpec{}, fmt.Errorf("invalid signing policy %q", policy)
}

// RetiredDecryptingSlots returns all 20 retired key management slots (0x82-0x95).
func RetiredDecryptingSlots() []pivgo.Slot {
	var slots []pivgo.Slot
	for i := uint32(0x82); i <= 0x95; i++ {
		s, _ := pivgo.RetiredKeyManagementSlot(i)
		slots = append(slots, s)
	}
	return slots
}
