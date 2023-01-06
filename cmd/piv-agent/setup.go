package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/smlx/piv-agent/internal/pinentry"
	"github.com/smlx/piv-agent/internal/securitykey"
	"golang.org/x/crypto/ssh/terminal"
)

// SetupCmd represents the setup command.
type SetupCmd struct {
	Card             string   `kong:"help='Specify a smart card device'"`
	ResetSecurityKey bool     `kong:"help='Overwrite any existing keys'"`
	PIN              uint64   `kong:"help='Set the PIN/PUK of the device (6-8 digits). Will be prompted interactively if not provided.'"`
	SigningKeys      []string `kong:"default='cached,always,never',enum='cached,always,never',help='Generate signing keys with various touch policies (possible values: cached,always,never)'"`
	DecryptingKeys   []string `kong:"default='cached,always,never',enum='cached,always,never',help='Generate decrypting keys with various touch policies (possible values: cached,always,never)'"`
}

// interactiveNewPIN prompts twice for a new PIN.
func interactiveNewPIN() (uint64, error) {
	fmt.Print("Enter a new PIN/PUK (6-8 digits): ")
	rawPIN, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return 0, fmt.Errorf("couldn't read PIN/PUK: %w", err)
	}
	pin, err := strconv.ParseUint(string(rawPIN), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid characters: %w", err)
	}
	fmt.Print("Repeat PIN/PUK: ")
	repeat, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return 0, fmt.Errorf("couldn't read PIN/PUK: %w", err)
	}
	if !bytes.Equal(repeat, rawPIN) {
		return 0, fmt.Errorf("PIN/PUK entries not equal")
	}
	return pin, nil
}

// Run the setup command to configure a security key.
func (cmd *SetupCmd) Run() error {
	// if PIN has not been specified, ask interactively
	var err error
	if cmd.PIN == 0 {
		cmd.PIN, err = interactiveNewPIN()
		if err != nil {
			return err
		}
	}
	if cmd.PIN < 100000 || cmd.PIN > 99999999 {
		return fmt.Errorf("invalid PIN, must be 6-8 digits")
	}
	k, err := securitykey.New(cmd.Card, pinentry.New("pinentry"))
	if err != nil {
		return fmt.Errorf("couldn't get security key: %v", err)
	}
	err = k.Setup(strconv.FormatUint(cmd.PIN, 10), version,
		cmd.ResetSecurityKey, cmd.SigningKeys, cmd.DecryptingKeys)
	if errors.Is(err, securitykey.ErrKeySetUp) {
		return fmt.Errorf("--reset-security-key not specified: %w", err)
	}
	return err
}
