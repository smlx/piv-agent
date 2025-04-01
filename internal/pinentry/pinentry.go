// Package pinentry implements a PIN/passphrase entry dialog.
package pinentry

import (
	"fmt"

	gpm "github.com/twpayne/go-pinentry-minimal/pinentry"
)

// A SecurityKey is a physical hardware token that requires a PIN.
type SecurityKey interface {
	Card() string
	Retries() (int, error)
	Serial() uint32
}

// PINEntry implements useful pinentry service methods.
type PINEntry struct {
	binaryName string
}

// New initialises a new PINEntry.
func New(binaryName string) *PINEntry {
	return &PINEntry{
		binaryName: binaryName,
	}
}

// GetPin uses pinentry to get the pin of the given token.
func (pe *PINEntry) GetPin(k SecurityKey) func() (string, error) {
	return func() (string, error) {
		r, err := k.Retries()
		if err != nil {
			return "", fmt.Errorf("couldn't get retries for security key: %w", err)
		}
		c, err := gpm.NewClient(
			gpm.WithBinaryName(pe.binaryName),
			gpm.WithTitle("piv-agent PIN Prompt"),
			gpm.WithPrompt("Please enter PIN:"),
			gpm.WithDesc(
				fmt.Sprintf("%s #%d\r(%d attempts remaining)",
					k.Card(), k.Serial(), r)),
			// optional PIN cache with yubikey-agent compatibility
			gpm.WithOption("allow-external-password-cache"),
			gpm.WithKeyInfo(fmt.Sprintf("--yubikey-id-%d", k.Serial())),
		)
		if err != nil {
			return "", fmt.Errorf("couldn't get pinentry client: %w", err)
		}
		defer c.Close() // nolint: errcheck
		pin, _, err := c.GetPIN()
		return pin, err
	}
}

// GetPassphrase uses pinentry to get the passphrase of the given key file.
func (pe *PINEntry) GetPassphrase(desc, keyID string, tries int) ([]byte, error) {
	c, err := gpm.NewClient(
		gpm.WithBinaryName(pe.binaryName),
		gpm.WithTitle("piv-agent Passphrase Prompt"),
		gpm.WithPrompt("Please enter passphrase"),
		gpm.WithDesc(fmt.Sprintf("%s\r(%d attempts remaining)", desc, tries)),

		// optional PIN cache with yubikey-agent compatibility
		gpm.WithOption("allow-external-password-cache"),
		gpm.WithKeyInfo(keyID),
	)
	if err != nil {
		return nil, fmt.Errorf("couldn't get pinentry client: %w", err)
	}
	defer c.Close() // nolint: errcheck
	pin, _, err := c.GetPIN()
	return []byte(pin), err
}
