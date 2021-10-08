package securitykey

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

// Setup configures the SecurityKey to work with piv-agent.
func (k *SecurityKey) Setup(pin, version string, reset bool,
	signingKeys []string, decryptionKey bool) error {
	_, err := k.yubikey.Certificate(piv.SlotAuthentication)
	if err == nil {
		if !reset {
			return ErrNotReset
		}
		if err = k.yubikey.Reset(); err != nil {
			return fmt.Errorf("couldn't reset security key: %v", err)
		}
	} else if !errors.Is(err, piv.ErrNotFound) {
		return fmt.Errorf("couldn't get certificate: %v", err)
	}
	var mgmtKey [24]byte
	if _, err := rand.Read(mgmtKey[:]); err != nil {
		return fmt.Errorf("couldn't get random bytes: %v", err)
	}
	err = k.yubikey.SetManagementKey(piv.DefaultManagementKey, mgmtKey)
	if err != nil {
		return fmt.Errorf("couldn't set management key: %v", err)
	}
	err = k.yubikey.SetMetadata(mgmtKey, &piv.Metadata{ManagementKey: &mgmtKey})
	if err != nil {
		return fmt.Errorf("couldn't store management key: %v", err)
	}
	if err = k.yubikey.SetPIN(piv.DefaultPIN, pin); err != nil {
		return fmt.Errorf("couldn't set PIN: %v", err)
	}
	if err = k.yubikey.SetPUK(piv.DefaultPUK, pin); err != nil {
		return fmt.Errorf("couldn't set PUK: %v", err)
	}
	// setup signing keys
	for _, p := range signingKeys {
		err := k.configureSlot(mgmtKey, defaultSignSlots[p], version)
		if err != nil {
			return fmt.Errorf("couldn't configure slot %v: %v", defaultSignSlots[p], err)
		}
	}
	// setup decrypt key
	if decryptionKey {
		err := k.configureSlot(mgmtKey, defaultDecryptSlots["cached"], version)
		if err != nil {
			return fmt.Errorf("couldn't configure slot %v: %v",
				defaultDecryptSlots["cached"], err)
		}
	}
	return nil
}

func (k *SecurityKey) configureSlot(mgmtKey [24]byte, spec SlotSpec,
	version string) error {
	pub, err := k.yubikey.GenerateKey(mgmtKey, spec.Slot, piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: spec.TouchPolicy,
	})
	if err != nil {
		return fmt.Errorf("couldn't generate key: %v", err)
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
			CommonName: "piv-agent key",
		},
		NotAfter:     time.Now().AddDate(64, 0, 0),
		NotBefore:    time.Now(),
		SerialNumber: serial,
		KeyUsage:     x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub,
		priv)
	if err != nil {
		return fmt.Errorf("couldn't create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("couldn't parse certificate: %w", err)
	}
	if err = k.yubikey.SetCertificate(mgmtKey, spec.Slot, cert); err != nil {
		return fmt.Errorf("couldn't set certificate: %w", err)
	}
	return nil
}
