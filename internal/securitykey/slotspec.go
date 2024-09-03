package securitykey

import pivgo "github.com/go-piv/piv-go/v2/piv"

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

var alwaysDecryptSlot, _ = pivgo.RetiredKeyManagementSlot(0x82)
var neverDecryptSlot, _ = pivgo.RetiredKeyManagementSlot(0x83)

// defaultDecryptSlots represents the slot specifications for decrypting
// operations. By using additional "retired" slots we can enable multiple touch
// policies for decrypt.
var defaultDecryptSlots = map[string]SlotSpec{
	// Slot 9d: Key Management
	// This certificate and its associated private key is used for encryption for
	// the purpose of confidentiality. This slot is used for things like
	// encrypting e-mails or files. The end user PIN is required to perform any
	// private key operations. Once the PIN has been provided successfully,
	// multiple private key operations may be performed without additional
	// cardholder consent.
	"cached": {pivgo.SlotKeyManagement, pivgo.TouchPolicyCached},
	// "Retired" key management slot with an "always" touch policy.
	"always": {alwaysDecryptSlot, pivgo.TouchPolicyAlways},
	// "Retired" key management slot with a "never" touch policy.
	"never": {neverDecryptSlot, pivgo.TouchPolicyNever},
}
