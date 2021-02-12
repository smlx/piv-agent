package agent

import (
	"fmt"

	"github.com/gopasspw/gopass/pkg/pinentry"
	"github.com/smlx/piv-agent/internal/token"
)

func pinEntry(sk *token.SecurityKey) func() (string, error) {
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
		r, err := sk.Key.Retries()
		if err != nil {
			return "", fmt.Errorf("couldn't get retries for security key: %w", err)
		}
		err = p.Set("desc",
			fmt.Sprintf("serial number: %d, attempts remaining: %d", sk.Serial, r))
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
		err = p.Set("KEYINFO", fmt.Sprintf("--yubikey-id-%d", sk.Serial))
		if err != nil {
			return "", fmt.Errorf("couldn't set KEYINFO on PIN pinentry: %w", err)
		}
		pin, err := p.GetPin()
		return string(pin), err
	}
}

func getPassphrase(keyPath, fingerprint string) ([]byte, error) {
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
