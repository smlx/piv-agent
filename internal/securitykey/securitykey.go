// Package securitykey provides an interface to a physical security key such as
// a Yubikey.
package securitykey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"sync"

	pivgo "github.com/go-piv/piv-go/v2/piv"
	"github.com/smlx/piv-agent/internal/pinentry"
	"golang.org/x/crypto/ssh"
)

// CryptoKey represents a cryptographic key on a hardware security device.
type CryptoKey struct {
	SlotSpec SlotSpec
	Public   crypto.PublicKey
}

// SigningKey is a public signing key on a security key / hardware token.
type SigningKey struct {
	CryptoKey
	PubSSH ssh.PublicKey
}

// A SecurityKey is a physical hardware token which implements PIV, such as a
// Yubikey. It provides an abstraction and caching around a pivgo.YubiKey.
type SecurityKey struct {
	card     string
	serial   uint32
	yubikey  *pivgo.YubiKey
	pinentry *pinentry.PINEntry

	mu             sync.Mutex // guards the cached fields below
	validCache     bool
	signingKeys    []SigningKey
	decryptingKeys []CryptoKey
	cryptoKeys     []CryptoKey
	certificates   map[uint32]*x509.Certificate
	certErrors     map[uint32]error
}

// SeedFileIDOID is the custom OID used to store the 8-byte FileID of the ML-KEM
// seed in the X.509 certificate on the YubiKey.
// It uses the smlx Private Enterprise Number 65955.
var SeedFileIDOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65955, 1, 1}

// TouchPolicyOID is the OID for the touch policy extension.
// See https://docs.yubico.com/hardware/oid/oid-piv-arc.html#sample-oid-with-piv-type
var TouchPolicyOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}

// KeyTag returns a 4-byte truncated SHA256 hash of the uncompressed P-256
// curve point. This short tag is used to uniquely identify the key and
// cryptographically bind data (such as age seed files) to this PIV key.
func (c *CryptoKey) KeyTag() ([4]byte, error) {
	ecdsaPub, ok := c.Public.(*ecdsa.PublicKey)
	if !ok {
		return [4]byte{}, fmt.Errorf("public key is not ECDSA")
	}
	ecdhPub, err := ecdsaPub.ECDH()
	if err != nil {
		return [4]byte{}, fmt.Errorf("couldn't convert to ECDH: %v", err)
	}
	b := ecdhPub.Bytes()
	hash := sha256.Sum256(b)
	return [4]byte(hash[:4]), nil
}

// New returns a security key identified by card string.
func New(card string, pe *pinentry.PINEntry) (*SecurityKey, error) {
	yk, err := pivgo.Open(card)
	if err != nil {
		return nil, fmt.Errorf(`couldn't open card "%s": %v`, card, err)
	}
	serial, err := yk.Serial()
	if err != nil {
		return nil, fmt.Errorf(`couldn't get serial for card "%s": %v`,
			card, err)
	}

	k := &SecurityKey{
		card:     card,
		serial:   serial,
		yubikey:  yk,
		pinentry: pe,
	}

	return k, nil
}

// ExtractFileIDFromCert returns the FileID from the custom OID extension, or nil.
func ExtractFileIDFromCert(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(SeedFileIDOID) {
			if len(ext.Value) == 8 {
				return ext.Value, nil
			}
			return nil, fmt.Errorf("invalid file ID length in certificate: %d", len(ext.Value))
		}
	}
	return nil, nil
}

func (k *SecurityKey) loadCache() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.validCache {
		return nil
	}

	certificates := map[uint32]*x509.Certificate{}
	certErrors := map[uint32]error{}
	var signingKeys []SigningKey
	var decryptingKeys []CryptoKey
	var cryptoKeys []CryptoKey

	for _, s := range defaultSignSlots {
		// load cert
		cert, err := k.yubikey.Certificate(s.Slot)
		certErrors[s.Slot.Key] = err
		if errors.Is(err, pivgo.ErrNotFound) {
			continue // no certificate in this slot, so no key available
		}
		if err != nil {
			return fmt.Errorf(
				"couldn't get certificate for slot %x: %v", s.Slot.Key, err)
		}
		// cache cert
		certificates[s.Slot.Key] = cert
		// load keys
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid public key type: %T", cert.PublicKey)
		}
		pubSSH, err := ssh.NewPublicKey(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("couldn't convert public key: %v", err)
		}
		ck := CryptoKey{Public: pubKey, SlotSpec: s}
		cryptoKeys = append(cryptoKeys, ck)
		signingKeys = append(signingKeys, SigningKey{
			CryptoKey: ck,
			PubSSH:    pubSSH,
		})
	}

	for _, slot := range RetiredDecryptingSlots() {
		cert, err := k.yubikey.Certificate(slot)
		certErrors[slot.Key] = err
		if errors.Is(err, pivgo.ErrNotFound) {
			continue // no certificate in this slot, so no key available
		}
		if err != nil {
			return fmt.Errorf(
				"couldn't get certificate for slot %x: %v", slot.Key, err)
		}

		// cache cert
		certificates[slot.Key] = cert

		// check if it's our decrypting key
		fileID, err := ExtractFileIDFromCert(cert)
		if err != nil {
			return fmt.Errorf("couldn't extract file ID from cert for slot %x: %w", slot.Key, err)
		}
		if fileID == nil {
			continue // not a piv-agent decrypting slot
		}

		// load keys
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid public key type: %T", cert.PublicKey)
		}

		touchPolicy := pivgo.TouchPolicyAlways
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(TouchPolicyOID) {
				if len(ext.Value) == 2 {
					touchPolicy = pivgo.TouchPolicy(ext.Value[1])
				}
			}
		}
		s := SlotSpec{Slot: slot, TouchPolicy: touchPolicy}

		ck := CryptoKey{Public: pubKey, SlotSpec: s}
		cryptoKeys = append(cryptoKeys, ck)
		decryptingKeys = append(decryptingKeys, ck)
	}

	// store cache
	k.signingKeys = signingKeys
	k.decryptingKeys = decryptingKeys
	k.cryptoKeys = cryptoKeys
	k.certificates = certificates
	k.certErrors = certErrors
	k.validCache = true
	return nil
}

// InvalidateCache clears cached certificates and keys.
func (k *SecurityKey) InvalidateCache() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.validCache = false
	return nil
}

// Certificate returns the X.509 certificate for a slot.
func (k *SecurityKey) Certificate(slot pivgo.Slot) (*x509.Certificate, error) {
	if err := k.loadCache(); err != nil {
		return nil, fmt.Errorf("couldn't load cache: %v", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.certificates[slot.Key], k.certErrors[slot.Key]
}

// Retries returns the number of attempts remaining to enter the correct PIN.
func (k *SecurityKey) Retries() (int, error) {
	return k.yubikey.Retries()
}

// Serial returns the serial number of the SecurityKey.
func (k *SecurityKey) Serial() uint32 {
	return k.serial
}

// Version returns the firmware version of the SecurityKey.
func (k *SecurityKey) Version() string {
	pv := k.yubikey.Version()
	return fmt.Sprintf("%d.%d.%d", pv.Major, pv.Minor, pv.Patch)
}

// Formfactor returns the form factor of the SecurityKey device.
func (k *SecurityKey) FormFactor() (string, error) {
	ff, err := k.yubikey.FormFactor()
	return ff.String(), err
}

// IsFactoryState checks if the default management key is in use and the slots
// used by piv-agent are empty.
func (k *SecurityKey) IsFactoryState() (bool, error) {
	for _, r := range k.Statuses(nil) {
		if r.Status != SlotStatusNotSetup {
			return false, nil
		}
	}
	// test if management key is set by setting it to the default value,
	// authenticated using the default value
	err := k.yubikey.SetManagementKey(
		pivgo.DefaultManagementKey,
		pivgo.DefaultManagementKey)
	if err != nil {
		// swallow error here: there is no distinct type returned from piv-go, and
		// it likely means that the default management key has been changed.
		return false, nil
	}

	return true, nil
}

// SigningKeys returns the slice of cryptographic signing keys held by the
// SecurityKey.
func (k *SecurityKey) SigningKeys() ([]SigningKey, error) {
	if err := k.loadCache(); err != nil {
		return nil, fmt.Errorf("couldn't load cache: %v", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.signingKeys, nil
}

// DecryptingKeys returns the slice of cryptographic decrypting keys held by
// the SecurityKey.
func (k *SecurityKey) DecryptingKeys() ([]CryptoKey, error) {
	if err := k.loadCache(); err != nil {
		return nil, fmt.Errorf("couldn't load cache: %v", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.decryptingKeys, nil
}

// CryptoKeys returns the slice of cryptographic signing and decrypting keys
// held by the SecurityKey.
func (k *SecurityKey) CryptoKeys() ([]CryptoKey, error) {
	if err := k.loadCache(); err != nil {
		return nil, fmt.Errorf("couldn't load cache: %v", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.cryptoKeys, nil
}

// PrivateKey returns the private key of the given public signing key.
func (k *SecurityKey) PrivateKey(c *CryptoKey) (crypto.PrivateKey, error) {
	return k.yubikey.PrivateKey(c.SlotSpec.Slot, c.Public,
		pivgo.KeyAuth{PINPrompt: k.pinentry.GetPin(k)})
}

// Close closes the underlying yubikey.
func (k *SecurityKey) Close() error {
	return k.yubikey.Close()
}

// AttestationCertificate returns the attestation certificate of the underlying
// yubikey.
func (k *SecurityKey) AttestationCertificate() (*x509.Certificate, error) {
	return k.yubikey.AttestationCertificate()
}

// Card returns the card identifier.
func (k *SecurityKey) Card() string {
	return k.card
}
