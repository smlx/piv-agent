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

	pivgo "github.com/go-piv/piv-go/v2/piv"
)

// ErrKeySetUp is returned from Setup when the security key is already set up
// and reset is false.
var ErrKeySetUp = errors.New("security key already set up")

// checkSlotSetUp checks if the provided slot is set up, returning true if the
// slot is set up and false otherwise.
func (k *SecurityKey) checkSlotSetUp(s SlotSpec) (bool, error) {
	_, err := k.yubikey.Certificate(s.Slot)
	if err == nil {
		return true, nil
	} else if errors.Is(err, pivgo.ErrNotFound) {
		return false, nil
	}
	return false, fmt.Errorf("couldn't check slot certificate: %v", err)
}

// checkSlotsSetUp checks if the provided slots are set up returning true if
// any of the slots are set up, and false otherwise.
func (k *SecurityKey) checkSlotsSetUp(signingKeys []string,
	decryptingKeys []string) (bool, error) {
	for _, p := range signingKeys {
		setUp, err := k.checkSlotSetUp(defaultSignSlots[p])
		if err != nil {
			return false, err
		}
		if setUp {
			return true, nil
		}
	}
	for _, p := range decryptingKeys {
		setUp, err := k.checkSlotSetUp(defaultDecryptSlots[p])
		if err != nil {
			return false, err
		}
		if setUp {
			return true, nil
		}
	}
	return false, nil
}

// Setup configures the SecurityKey to work with piv-agent.
func (k *SecurityKey) Setup(pin, version string, reset bool,
	signingKeys []string, decryptingKeys []string) error {
	var err error
	if !reset {
		setUp, err := k.checkSlotsSetUp(signingKeys, decryptingKeys)
		if err != nil {
			return fmt.Errorf("couldn't check slots: %v", err)
		}
		if setUp {
			return ErrKeySetUp
		}
	}
	// reset security key
	if err = k.yubikey.Reset(); err != nil {
		return fmt.Errorf("couldn't reset security key: %v", err)
	}
	// generate management key and store on the security key
	var mgmtKey = make([]byte, 24)
	if _, err := rand.Read(mgmtKey); err != nil {
		return fmt.Errorf("couldn't get random bytes: %v", err)
	}
	err = k.yubikey.SetManagementKey(pivgo.DefaultManagementKey, mgmtKey)
	if err != nil {
		return fmt.Errorf("couldn't set management key: %v", err)
	}
	err = k.yubikey.SetMetadata(mgmtKey, &pivgo.Metadata{ManagementKey: &mgmtKey})
	if err != nil {
		return fmt.Errorf("couldn't store management key: %v", err)
	}
	// set pin/puk
	if err = k.yubikey.SetPIN(pivgo.DefaultPIN, pin); err != nil {
		return fmt.Errorf("couldn't set PIN: %v", err)
	}
	if err = k.yubikey.SetPUK(pivgo.DefaultPUK, pin); err != nil {
		return fmt.Errorf("couldn't set PUK: %v", err)
	}
	// setup signing keys
	for _, p := range signingKeys {
		err := k.configureSlot(mgmtKey, defaultSignSlots[p], version)
		if err != nil {
			return fmt.Errorf("couldn't configure slot %v: %v",
				defaultSignSlots[p], err)
		}
	}
	// setup decrypt keys
	for _, p := range decryptingKeys {
		err := k.configureSlot(mgmtKey, defaultDecryptSlots[p], version)
		if err != nil {
			return fmt.Errorf("couldn't configure slot %v: %v",
				defaultDecryptSlots[p], err)
		}
	}
	return nil
}

func (k *SecurityKey) configureSlot(mgmtKey []byte, spec SlotSpec,
	version string) error {
	pub, err := k.yubikey.GenerateKey(mgmtKey, spec.Slot, pivgo.Key{
		Algorithm:   pivgo.AlgorithmEC256,
		PINPolicy:   pivgo.PINPolicyOnce,
		TouchPolicy: spec.TouchPolicy,
	})
	if err != nil {
		return fmt.Errorf("couldn't generate key for spec %v: %v", spec, err)
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
