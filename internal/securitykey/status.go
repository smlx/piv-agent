package securitykey

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	pivgo "github.com/go-piv/piv-go/v2/piv"
)

// SlotStatus represents the compatibility state of a slot.
type SlotStatus int

const (
	// SlotStatusNotSetup means the slot is empty (blue).
	SlotStatusNotSetup SlotStatus = iota
	// SlotStatusPivAgent means the slot is set up by piv-agent (green).
	SlotStatusPivAgent
	// SlotStatusCompatible means the slot is set up with a compatible key (yellow).
	SlotStatusCompatible
	// SlotStatusIncompatible means the slot is set up with an incompatible key (red).
	SlotStatusIncompatible
)

// SlotType represents whether the slot is used for signing or decrypting.
type SlotType int

const (
	SlotTypeSigning SlotType = iota
	SlotTypeDecrypting
)

func (st SlotType) String() string {
	switch st {
	case SlotTypeSigning:
		return "Signing"
	case SlotTypeDecrypting:
		return "Decrypting"
	default:
		return "Unknown"
	}
}

// TouchPolicy represents the touch policy requirement.
type TouchPolicy int

const (
	TouchPolicyCached TouchPolicy = iota
	TouchPolicyAlways
	TouchPolicyNever
)

func (tp TouchPolicy) String() string {
	switch tp {
	case TouchPolicyCached:
		return "cached"
	case TouchPolicyAlways:
		return "always"
	case TouchPolicyNever:
		return "never"
	default:
		return "unknown"
	}
}

// SlotReport contains the status and information about a slot.
type SlotReport struct {
	Slot        pivgo.Slot
	Type        SlotType
	TouchPolicy TouchPolicy
	Status      SlotStatus
	Error       error
}

// String generates a user-readable description of the slot.
func (r *SlotReport) String() string {
	return fmt.Sprintf("Slot %x (%s, touch policy: %s)", r.Slot.Key, r.Type.String(), r.TouchPolicy.String())
}

// Status checks the status of a specific slot on the security key.
func (k *SecurityKey) Status(slot pivgo.Slot, slotType SlotType, policy TouchPolicy) SlotReport {
	report := SlotReport{
		Slot:        slot,
		Type:        slotType,
		TouchPolicy: policy,
	}

	cert, err := k.Certificate(slot)
	if err != nil {
		if errors.Is(err, pivgo.ErrNotFound) {
			report.Status = SlotStatusNotSetup
		} else {
			report.Status = SlotStatusIncompatible
			report.Error = err
		}
		return report
	}

	// Check if set up by piv-agent
	var actualOrg string
	if len(cert.Subject.Organization) > 0 {
		actualOrg = cert.Subject.Organization[0]
	} else if len(cert.Issuer.Organization) > 0 {
		actualOrg = cert.Issuer.Organization[0]
	}

	isPivAgentOrg := slices.Contains(cert.Subject.Organization, "piv-agent") || slices.Contains(cert.Issuer.Organization, "piv-agent")

	// Check compatibility
	if _, isECDSA := cert.PublicKey.(*ecdsa.PublicKey); !isECDSA {
		report.Status = SlotStatusIncompatible
		report.Error = fmt.Errorf("key type not ECDSA")
		return report
	}

	if slotType == SlotTypeSigning && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		report.Status = SlotStatusIncompatible
		report.Error = fmt.Errorf("certificate key usage does not permit digital signature")
		return report
	}
	if slotType == SlotTypeDecrypting && cert.KeyUsage&x509.KeyUsageKeyAgreement == 0 {
		report.Status = SlotStatusIncompatible
		report.Error = fmt.Errorf("certificate key usage does not permit key agreement")
		return report
	}

	if isPivAgentOrg && cert.Subject.CommonName == "piv-agent key" {
		report.Status = SlotStatusPivAgent
		return report
	}

	report.Status = SlotStatusCompatible
	if !isPivAgentOrg {
		if actualOrg != "" {
			report.Error = fmt.Errorf("unexpected organization: %s", actualOrg)
		}
	} else if cert.Subject.CommonName != "piv-agent key" && cert.Subject.CommonName != "" {
		report.Error = fmt.Errorf("unexpected common name: %s", cert.Subject.CommonName)
	}

	return report
}

// Statuses returns a report for all slots used by piv-agent, or a subset of slots if specified.
func (k *SecurityKey) Statuses(slotFilter []uint32) []SlotReport {
	var reports []SlotReport

	slotsToCheck := []struct {
		Slot        pivgo.Slot
		Type        SlotType
		TouchPolicy TouchPolicy
	}{
		{defaultSignSlots["cached"].Slot, SlotTypeSigning, TouchPolicyCached},
		{defaultSignSlots["always"].Slot, SlotTypeSigning, TouchPolicyAlways},
		{defaultSignSlots["never"].Slot, SlotTypeSigning, TouchPolicyNever},
		{defaultDecryptSlots["cached"].Slot, SlotTypeDecrypting, TouchPolicyCached},
		{defaultDecryptSlots["always"].Slot, SlotTypeDecrypting, TouchPolicyAlways},
		{defaultDecryptSlots["never"].Slot, SlotTypeDecrypting, TouchPolicyNever},
	}

	for _, s := range slotsToCheck {
		if len(slotFilter) > 0 && !slices.Contains(slotFilter, s.Slot.Key) {
			continue
		}
		report := k.Status(s.Slot, s.Type, s.TouchPolicy)
		reports = append(reports, report)
	}

	return reports
}
