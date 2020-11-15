package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/go-piv/piv-go/piv"
)

// ErrNotReset is returned from Setup when the security key is already set up
// and reset is false.
var ErrNotReset = errors.New("security key already set up")

// Setup sets up the given security key / hardware token
func Setup(k *piv.YubiKey, pin, version string, reset, allTouchPolicies bool) error {
	_, err := k.Certificate(piv.SlotAuthentication)
	if err == nil {
		if !reset {
			return ErrNotReset
		}
		if err = k.Reset(); err != nil {
			return fmt.Errorf("couldn't reset security key: %w", err)
		}
	} else if !errors.Is(err, piv.ErrNotFound) {
		return fmt.Errorf("couldn't get certificate: %w", err)
	}
	var mk [24]byte
	if _, err := rand.Read(mk[:]); err != nil {
		return fmt.Errorf("couldn't get random bytes: %w", err)
	}
	if err = k.SetManagementKey(piv.DefaultManagementKey, mk); err != nil {
		return fmt.Errorf("couldn't set management key: %w", err)
	}
	if err = k.SetMetadata(mk, &piv.Metadata{ManagementKey: &mk}); err != nil {
		return fmt.Errorf("couldn't store management key: %w", err)
	}
	if err = k.SetPIN(piv.DefaultPIN, pin); err != nil {
		return fmt.Errorf("couldn't set PIN: %w", err)
	}
	if err = k.SetPUK(piv.DefaultPUK, pin); err != nil {
		return fmt.Errorf("couldn't set PUK: %w", err)
	}
	keySpecs := []KeySpec{
		{Slot: piv.SlotAuthentication, TouchPolicy: piv.TouchPolicyCached},
	}
	if allTouchPolicies {
		keySpecs = AllKeySpecs
	}
	for _, ks := range keySpecs {
		if err = configureSlot(k, mk, ks.Slot, ks.TouchPolicy, version); err != nil {
			return fmt.Errorf("couldn't configure slot %v: %w", ks.Slot, err)
		}
	}
	return nil
}

func configureSlot(k *piv.YubiKey, mk [24]byte,
	slot piv.Slot, touchPolicy piv.TouchPolicy, version string) error {
	pub, err := k.GenerateKey(mk, slot, piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: touchPolicy,
	})
	if err != nil {
		return fmt.Errorf("couldn't generate key: %w", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("couldn't generate parent key: %w", err)
	}
	parent := &x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"piv-agent"},
			OrganizationalUnit: []string{version},
		},
		PublicKey: priv.Public(),
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("couldn't generate serial: %w", err)
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "SSH key",
		},
		NotAfter:     time.Now().AddDate(64, 0, 0),
		NotBefore:    time.Now(),
		SerialNumber: serial,
		KeyUsage:     x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return fmt.Errorf("couldn't create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("couldn't parse certificate: %w", err)
	}
	if err = k.SetCertificate(mk, slot, cert); err != nil {
		return fmt.Errorf("couldn't set certificate: %w", err)
	}
	return nil
}
