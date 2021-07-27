package pinentry

import (
	"fmt"

	"github.com/gopasspw/gopass/pkg/pinentry"
)

// A SecurityKey is a physical hardware token that requires a PIN.
type SecurityKey interface {
	Retries() (int, error)
	Serial() uint32
}

// PINEntry implements useful pinentry service methods.
type PINEntry struct{}

// GetPGPPassphrase uses pinentry to get the passphrase of the key with the
// given keygrip.
func (*PINEntry) GetPGPPassphrase(fingerprint string) ([]byte, error) {
	p, err := pinentry.New()
	if err != nil {
		return []byte{}, fmt.Errorf("couldn't get pinentry client: %w", err)
	}
	defer p.Close()
	err = p.Set("title", "piv-agent Passphrase Prompt")
	if err != nil {
		return nil,
			fmt.Errorf("couldn't set title on passphrase pinentry: %w", err)
	}
	err = p.Set("prompt", "Please enter passphrase")
	if err != nil {
		return nil,
			fmt.Errorf("couldn't set prompt on passphrase pinentry: %w", err)
	}
	err = p.Set("desc", fmt.Sprintf("PGP key fingerprint: %s", fingerprint))
	if err != nil {
		return nil,
			fmt.Errorf("couldn't set desc on passphrase pinentry: %w", err)
	}
	// optional PIN cache
	err = p.Option("allow-external-password-cache")
	if err != nil {
		return nil,
			fmt.Errorf("couldn't set option on passphrase pinentry: %w", err)
	}
	err = p.Set("KEYINFO", fingerprint)
	if err != nil {
		return nil,
			fmt.Errorf("couldn't set KEYINFO on passphrase pinentry: %w", err)
	}
	return p.GetPin()
}

// GetPin uses pinentry to get the pin of the given token.
func GetPin(k SecurityKey) func() (string, error) {
	return func() (string, error) {
		p, err := pinentry.New()
		if err != nil {
			return "", fmt.Errorf("couldn't get pinentry client: %w", err)
		}
		defer p.Close()
		err = p.Set("title", "piv-agent PIN Prompt")
		if err != nil {
			return "", fmt.Errorf("couldn't set title on PIN pinentry: %w", err)
		}
		r, err := k.Retries()
		if err != nil {
			return "", fmt.Errorf("couldn't get retries for security key: %w", err)
		}
		err = p.Set("desc",
			fmt.Sprintf("serial number: %d, attempts remaining: %d", k.Serial(), r))
		if err != nil {
			return "", fmt.Errorf("couldn't set desc on PIN pinentry: %w", err)
		}
		err = p.Set("prompt", "Please enter PIN:")
		if err != nil {
			return "", fmt.Errorf("couldn't set prompt on PIN pinentry: %w", err)
		}
		// optional PIN cache with yubikey-agent compatibility
		err = p.Option("allow-external-password-cache")
		if err != nil {
			return "", fmt.Errorf("couldn't set option on PIN pinentry: %w", err)
		}
		err = p.Set("KEYINFO", fmt.Sprintf("--yubikey-id-%d", k.Serial()))
		if err != nil {
			return "", fmt.Errorf("couldn't set KEYINFO on PIN pinentry: %w", err)
		}
		pin, err := p.GetPin()
		return string(pin), err
	}
}

// GetPassphrase uses pinentry to get the passphrase of the given key file.
func GetPassphrase(keyPath, fingerprint string) ([]byte, error) {
	p, err := pinentry.New()
	if err != nil {
		return []byte{}, fmt.Errorf("couldn't get pinentry client: %w", err)
	}
	defer p.Close()
	err = p.Set("title", "piv-agent Passphrase Prompt")
	if err != nil {
		return nil,
			fmt.Errorf("couldn't set title on passphrase pinentry: %w", err)
	}
	err = p.Set("prompt", "Please enter passphrase")
	if err != nil {
		return nil,
			fmt.Errorf("couldn't set prompt on passphrase pinentry: %w", err)
	}
	err = p.Set("desc",
		fmt.Sprintf("%s %s %s", keyPath, fingerprint[:25], fingerprint[25:]))
	if err != nil {
		return nil,
			fmt.Errorf("couldn't set desc on passphrase pinentry: %w", err)
	}
	// optional PIN cache
	err = p.Option("allow-external-password-cache")
	if err != nil {
		return nil,
			fmt.Errorf("couldn't set option on passphrase pinentry: %w", err)
	}
	err = p.Set("KEYINFO", fingerprint)
	if err != nil {
		return nil,
			fmt.Errorf("couldn't set KEYINFO on passphrase pinentry: %w", err)
	}
	return p.GetPin()
}
