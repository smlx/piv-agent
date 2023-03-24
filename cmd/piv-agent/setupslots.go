package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/smlx/piv-agent/internal/pinentry"
	"github.com/smlx/piv-agent/internal/securitykey"
	"golang.org/x/term"
)

// SetupSlotsCmd represents the setup command.
type SetupSlotsCmd struct {
	Card           string   `kong:"help='Specify a smart card device'"`
	ResetSlots     bool     `kong:"help='Overwrite existing keys in the targeted slots'"`
	PIN            uint64   `kong:"help='The PIN/PUK of the device (6-8 digits). Will be prompted interactively if not provided.'"`
	SigningKeys    []string `kong:"enum='cached,always,never',help='Set up slots for signing keys with various touch policies (possible values cached,always,never)'"`
	DecryptingKeys []string `kong:"enum='cached,always,never',help='Set up slots for a decrypting keys with various touch polcies (possible values cached,always,never)'"`
}

// interactivePIN prompts once for an existing PIN.
func interactivePIN() (uint64, error) {
	fmt.Print("Enter the PIN/PUK (6-8 digits): ")
	rawPIN, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return 0, fmt.Errorf("couldn't read PIN/PUK: %w", err)
	}
	pin, err := strconv.ParseUint(string(rawPIN), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid characters: %w", err)
	}
	return pin, nil
}

// Run the setup-slot command to configure a slot on a security key.
func (cmd *SetupSlotsCmd) Run() error {
	// validate keys specified
	if len(cmd.SigningKeys) == 0 && len(cmd.DecryptingKeys) == 0 {
		return fmt.Errorf("at least one key slot must be specified via --signing-keys=... or --decrypting-keys=... ")
	}
	// if PIN has not been specified, ask interactively
	var err error
	if cmd.PIN == 0 {
		cmd.PIN, err = interactivePIN()
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
	err = k.SetupSlots(strconv.FormatUint(cmd.PIN, 10), version, cmd.ResetSlots,
		cmd.SigningKeys, cmd.DecryptingKeys)
	if errors.Is(err, securitykey.ErrKeySetUp) {
		return fmt.Errorf("--reset-slots not specified: %w", err)
	}
	return err
}
