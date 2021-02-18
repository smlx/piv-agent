package securitykey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"github.com/smlx/piv-agent/internal/pinentry"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/ssh"
)

// SigningKey is a public signing key on a security key / hardware token.
type SigningKey struct {
	SlotSpec *SlotSpec
	Public   crypto.PublicKey
	PubSSH   ssh.PublicKey
	PubPGP   *packet.PublicKey
}

// A SecurityKey is a physical hardware token which implements PIV, such as a
// Yubikey. It provides a convenient abstraction around the low-level
// piv.YubiKey object.
type SecurityKey struct {
	card        string
	serial      uint32
	yubikey     *piv.YubiKey
	signingKeys []SigningKey
}

// signingKeys returns the signing keys available on the given yubikey.
func signingKeys(yk *piv.YubiKey) ([]SigningKey, error) {
	var signingKeys []SigningKey
	for _, s := range defaultSignSlots {
		cert, err := yk.Certificate(s.Slot)
		if err != nil {
			if errors.Is(err, piv.ErrNotFound) {
				continue
			}
			return nil, fmt.Errorf("couldn't get certificate for slot %x: %v",
				s.Slot.Key, err)
		}
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid public key type: %T", cert.PublicKey)
		}
		pubSSH, err := ssh.NewPublicKey(cert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("couldn't convert public key: %v", err)
		}
		signingKeys = append(signingKeys, SigningKey{
			Public: pubKey,
			PubSSH: pubSSH,
			PubPGP: packet.NewECDSAPublicKey(cert.NotBefore, pubKey),
			SlotSpec: &SlotSpec{
				Slot:        s.Slot,
				TouchPolicy: s.TouchPolicy,
			},
		})
	}
	return signingKeys, nil
}

// New returns a security key identified by card string.
func New(card string) (*SecurityKey, error) {
	yk, err := piv.Open(card)
	if err != nil {
		return nil, fmt.Errorf(`couldn't open card "%s": %v`, card, err)
	}
	serial, err := yk.Serial()
	if err != nil {
		return nil, fmt.Errorf(`couldn't get serial for card "%s": %v`,
			card, err)
	}
	signingKeys, err := signingKeys(yk)
	if err != nil {
		return nil, fmt.Errorf(`couldn't get signing keys for card "%s": %v`,
			card, err)
	}
	return &SecurityKey{
		card:        card,
		serial:      serial,
		yubikey:     yk,
		signingKeys: signingKeys,
	}, nil
}

// Retries returns the number of attempts remaining to enter the correct PIN.
func (k *SecurityKey) Retries() (int, error) {
	return k.yubikey.Retries()
}

// Serial returns the serial number of the SecurityKey.
func (k *SecurityKey) Serial() uint32 {
	return k.serial
}

// SigningKeys returns the slice of signing keys held by the SecurityKey.
func (k *SecurityKey) SigningKeys() []SigningKey {
	return k.signingKeys
}

// PrivateKey returns the private key of the given public signing key.
func (k *SecurityKey) PrivateKey(s *SigningKey) (crypto.PrivateKey, error) {
	return k.yubikey.PrivateKey(s.SlotSpec.Slot, s.Public,
		piv.KeyAuth{PINPrompt: pinentry.GetPin(k)})
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
