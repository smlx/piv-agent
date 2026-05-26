package securitykey

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	pivgo "github.com/go-piv/piv-go/v2/piv"
)

type SetupOptions struct {
	FactoryReset   bool
	IsFactoryState bool
	SigningKeys    []string
	DecryptingKeys []string
	PIN            string
	NewPIN         string
}

// Setup configures the SecurityKey to work with piv-agent.
// Note: Slot configuration is sequential and non-atomic. An error during the
// process may leave the security key in a partially modified state.
func (k *SecurityKey) Setup(version string, opts SetupOptions) error {
	var err error
	var pin = opts.PIN
	var mgmtKey []byte
	// get the values of the pin and mgmtKey for the three states: reset,
	// factory, incremental.
	switch {
	case opts.FactoryReset:
		// reset and full init
		if err = k.yubikey.Reset(); err != nil {
			return fmt.Errorf("couldn't reset security key: %v", err)
		}
		// The applet has just been wiped, meaning its current PIN is
		// guaranteed to be the factory default. Update the local tracking variable.
		pin = pivgo.DefaultPIN
		fallthrough
	case opts.IsFactoryState:
		// for factory state (no reset), assume default pin if none is provided
		if pin == "" {
			pin = pivgo.DefaultPIN
		}
		if err = k.yubikey.SetPIN(pin, opts.NewPIN); err != nil {
			return fmt.Errorf("couldn't set PIN: %v", err)
		}
		pin = opts.NewPIN // pin has now changed
		if err = k.yubikey.SetPUK(pivgo.DefaultPUK, opts.NewPIN); err != nil {
			return fmt.Errorf("couldn't set PUK: %v", err)
		}
		mgmtKey = make([]byte, 24)
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
	default:
		metadata, err := k.yubikey.Metadata(pin)
		if err != nil {
			var authErr *pivgo.AuthErr
			if errors.As(err, &authErr) {
				return fmt.Errorf(
					"incorrect PIN: you have %d retries left before PIV applet is locked",
					authErr.Retries)
			}
			return fmt.Errorf("couldn't get key metadata: %v", err)
		}
		if metadata.ManagementKey != nil {
			mgmtKey = *metadata.ManagementKey
		} else {
			// metadata missing, so fall back to default management
			mgmtKey = make([]byte, 24)
			if _, err := rand.Read(mgmtKey); err != nil {
				return fmt.Errorf("couldn't get random bytes: %v", err)
			}
			err = k.yubikey.SetManagementKey(pivgo.DefaultManagementKey, mgmtKey)
			if err != nil {
				return fmt.Errorf(
					"device not in factory state but has no management key in metadata: "+
						"cannot proceed with incremental setup: %v", err)
			}
			err = k.yubikey.SetMetadata(mgmtKey, &pivgo.Metadata{ManagementKey: &mgmtKey})
			if err != nil {
				return fmt.Errorf("couldn't store management key: %v", err)
			}
		}

	}
	// At this point the device's basic setup is complete. `pin` and `mgmtKey`
	// contain the PIN and management key respectively. Proceed to set up slots.
	touchRequired := false
	for _, p := range opts.SigningKeys {
		if defaultSignSlots[p].TouchPolicy == pivgo.TouchPolicyAlways ||
			defaultSignSlots[p].TouchPolicy == pivgo.TouchPolicyCached {
			touchRequired = true
		}
	}
	for _, p := range opts.DecryptingKeys {
		if defaultDecryptSlots[p].TouchPolicy == pivgo.TouchPolicyAlways ||
			defaultDecryptSlots[p].TouchPolicy == pivgo.TouchPolicyCached {
			touchRequired = true
		}
	}
	if touchRequired {
		fmt.Println("👆 Touch the security key when it flashes to continue...")
	}
	// set up signing keys
	for _, p := range opts.SigningKeys {
		spec := defaultSignSlots[p]
		err = k.configureSlot(mgmtKey, pin, spec, version, x509.KeyUsageDigitalSignature)
		if err != nil {
			return fmt.Errorf("couldn't configure slot %v: %v", spec, err)
		}
	}
	// set up decrypt keys
	for _, p := range opts.DecryptingKeys {
		spec := defaultDecryptSlots[p]
		err = k.configureSlot(mgmtKey, pin, spec, version, x509.KeyUsageKeyAgreement)
		if err != nil {
			return fmt.Errorf("couldn't configure slot %v: %v", spec, err)
		}
	}

	if err := k.InvalidateCache(); err != nil {
		return fmt.Errorf("couldn't flush cache after setup: %v", err)
	}

	return nil
}

func (k *SecurityKey) configureSlot(mgmtKey []byte, pin string, spec SlotSpec,
	version string, keyUsage x509.KeyUsage) error {
	pub, err := k.yubikey.GenerateKey(mgmtKey, spec.Slot, pivgo.Key{
		Algorithm:   pivgo.AlgorithmEC256,
		PINPolicy:   pivgo.PINPolicyOnce,
		TouchPolicy: spec.TouchPolicy,
	})
	if err != nil {
		return fmt.Errorf("couldn't generate key for spec %v: %v", spec, err)
	}
	priv, err := k.yubikey.PrivateKey(spec.Slot, pub, pivgo.KeyAuth{PIN: pin})
	if err != nil {
		return fmt.Errorf("couldn't get private key: %v", err)
	}
	parent := &x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"piv-agent"},
			OrganizationalUnit: []string{version},
		},
		PublicKey: pub,
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("couldn't generate serial: %v", err)
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "piv-agent key",
		},
		NotAfter:     time.Now().AddDate(64, 0, 0), // 64 years should be enough for anyone
		NotBefore:    time.Now(),
		SerialNumber: serial,
		KeyUsage:     keyUsage,
		// https://docs.yubico.com/hardware/oid/oid-piv-arc.html#sample-oid-with-piv-type
		ExtraExtensions: []pkix.Extension{
			{
				Id:       []int{1, 3, 6, 1, 4, 1, 41482, 3, 8},
				Critical: false,
				Value:    []byte{byte(pivgo.PINPolicyOnce), byte(spec.TouchPolicy)},
			},
		},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub,
		priv)
	if err != nil {
		return fmt.Errorf("couldn't create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("couldn't parse certificate: %v", err)
	}
	if err = k.yubikey.SetCertificate(mgmtKey, spec.Slot, cert); err != nil {
		return fmt.Errorf("couldn't set certificate: %v", err)
	}
	return nil
}
