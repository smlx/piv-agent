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
		p.Set("title", "piv-agent PIN Prompt")
		r, err := sk.Key.Retries()
		if err != nil {
			return "", fmt.Errorf("couldn't get retries for security key: %w", err)
		}
		p.Set("desc",
			fmt.Sprintf("serial number: %d, attempts remaining: %d", sk.Serial, r))
		p.Set("prompt", "Please enter PIN:")
		// optional PIN cache with yubikey-agent compatibility
		p.Option("allow-external-password-cache")
		p.Set("KEYINFO", fmt.Sprintf("--yubikey-id-%d", sk.Serial))
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
	p.Set("title", "piv-agent Passphrase Prompt")
	p.Set("prompt", "Please enter passphrase")
	p.Set("desc", fmt.Sprintf("%s %s %s", keyPath,
		fingerprint[:25], fingerprint[25:]))
	// optional PIN cache
	p.Option("allow-external-password-cache")
	p.Set("KEYINFO", fingerprint)
	return p.GetPin()
}
