package main

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/smlx/piv-agent/internal/securitykey"
)

// SetupSlotsCmd represents the setup command.
type SetupSlotsCmd struct {
	Card           string   `kong:"help='Specify a smart card device'"`
	ResetSlots     bool     `kong:"help='Overwrite existing keys in the targeted slots'"`
	PIN            uint64   `kong:"help='The PIN/PUK of the device (6-8 digits). Will be prompted interactively if not provided.'"`
	SigningKeys    []string `kong:"required,enum='cached,always,never',help='Set up slots for signing keys with various touch policies (possible values cached,always,never)'"`
	DecryptingKeys []string `kong:"required,enum='cached,always,never',help='Set up slot for a decrypting key (possible values cached,always,never)'"`
}

// Run the setup-slot command to configure a slot on a security key.
func (cmd *SetupSlotsCmd) Run() error {
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
	k, err := securitykey.New(cmd.Card)
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
