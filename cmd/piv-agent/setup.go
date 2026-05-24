package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"

	"github.com/smlx/piv-agent/internal/keyservice/piv"
	"github.com/smlx/piv-agent/internal/pinentry"
	"github.com/smlx/piv-agent/internal/securitykey"
	"golang.org/x/term"
)

// SetupCmd represents the setup command.
type SetupCmd struct {
	Serial         uint32   `kong:"help='Specify the serial number of the security key to target'"`
	FactoryReset   bool     `kong:"help='Wipe all existing keys on the security key and perform a full reset of the PIV applet'"`
	Force          bool     `kong:"help='Bypass all interactive confirmation prompts'"`
	PIN            string   `kong:"xor='pin',help='Authenticate with this PIN. Prompted interactively if not provided.'"`
	NewPIN         string   `kong:"xor='pin',help='Set this as the new PIN/PUK during factory reset or initial setup. Prompted interactively if not provided.'"`
	SigningKeys    []string `kong:"enum='cached,always,never',help='Generate signing keys with various touch policies'"`
	DecryptingKeys []string `kong:"enum='cached,always,never',help='Generate decrypting keys with various touch policies'"`
}

// Help returns detailed help text for the setup command.
func (cmd *SetupCmd) Help() string {
	return `Setup operates in three distinct modes:

Initial Setup:
  Configure a new security key device.
  Example: piv-agent setup

Incremental Setup:
  Set up specific slots on an already configured device.
  Example: piv-agent setup --signing-keys=always

Factory Reset:
  Perform a reset of the PIV applet before setting up the device.
  Example: piv-agent setup --factory-reset

Setup will prompt before making any hardware configuration changes (use --force to skip).`
}

// validatePIN checks that the PIN is a string of 6 to 8 digits.
func validatePIN(pin string) error {
	if len(pin) < 6 || len(pin) > 8 {
		return fmt.Errorf("invalid PIN, must be 6-8 digits")
	}
	for _, r := range pin {
		if r < '0' || r > '9' {
			return fmt.Errorf("invalid PIN, must contain only digits")
		}
	}
	return nil
}

// readPIN safely reads a PIN from the terminal, restoring the terminal state
// if interrupted.
func readPIN() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	state, err := term.GetState(fd)
	if err != nil {
		return nil, fmt.Errorf("couldn't get terminal state: %v", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	defer signal.Stop(c)

	type result struct {
		pin []byte
		err error
	}
	res := make(chan result, 1)

	// leaks the goroutine on cancellation, but will be exiting imminently anyway
	go func() {
		pin, err := term.ReadPassword(fd)
		res <- result{pin, err}
	}()

	select {
	case <-c:
		_ = term.Restore(fd, state)
		return nil, fmt.Errorf("setup cancelled")
	case r := <-res:
		return r.pin, r.err
	}
}

// promptPIN prompts for a PIN/PUK, optionally confirming.
func promptPIN(prompt string, confirm bool) (string, error) {
	fmt.Print(prompt)
	rawPIN, err := readPIN()
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("couldn't read PIN/PUK: %v", err)
	}
	pin := strings.TrimSpace(string(rawPIN))
	if err := validatePIN(pin); err != nil {
		return "", err
	}
	if confirm {
		fmt.Print("Repeat to confirm: ")
		repeat, err := readPIN()
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("couldn't read PIN/PUK: %v", err)
		}
		repeatPin := strings.TrimSpace(string(repeat))
		if pin != repeatPin {
			return "", fmt.Errorf("PIN/PUK entries not equal")
		}
	}
	return pin, nil
}

// promptConfirm prompts the user to confirm an action.
func promptConfirm(prompt, expectedPhrase string, caseSensitive bool) (bool, error) {
	fmt.Print(prompt)
	response, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("couldn't read confirmation: %v", err)
	}
	response = strings.TrimSpace(response)
	if !caseSensitive {
		response = strings.ToLower(response)
		expectedPhrase = strings.ToLower(expectedPhrase)
	}
	if response != expectedPhrase {
		return false, fmt.Errorf("confirmation failed")
	}
	return true, nil
}

// confirmOverwrite prompts the user to confirm overwriting specific slots.
func confirmOverwrite(k *securitykey.SecurityKey, force bool, signingKeys []string, decryptingKeys []string) (bool, error) {
	statuses := k.Statuses(nil)
	var slots []string
	for _, status := range statuses {
		if status.Status == securitykey.SlotStatusIncompatible && status.Error != nil {
			return false, fmt.Errorf("couldn't check slot %s: %v", status.String(), status.Error)
		}
		// skip slots that the user isn't trying to configure
		slotOverwrite := false
		if status.Type == securitykey.SlotTypeSigning &&
			slices.Contains(signingKeys, status.TouchPolicy.String()) {
			slotOverwrite = true
		}
		if status.Type == securitykey.SlotTypeDecrypting &&
			slices.Contains(decryptingKeys, status.TouchPolicy.String()) {
			slotOverwrite = true
		}
		if !slotOverwrite {
			continue
		}
		// don't prompt for empty slots
		if status.Status != securitykey.SlotStatusNotSetup {
			slots = append(slots, status.String())
		}
	}
	if len(slots) == 0 {
		// not overwriting any slots
		return true, nil
	}
	if force {
		fmt.Printf("\nOverwriting the following slots due to --force:\n")
		for _, slot := range slots {
			fmt.Printf(" - %s\n", slot)
		}
		return true, nil
	}
	// interactive prompt
	expectedPhrase := "yes"
	fmt.Printf("\n⚠️ WARNING: The following slots are already set up. " +
		"This action will overwrite keys in listed slots. ⚠️\n")
	for _, slot := range slots {
		fmt.Printf(" - %s\n", slot)
	}
	return promptConfirm(
		fmt.Sprintf("Type %q to continue, or anything else to cancel: ", expectedPhrase),
		expectedPhrase,
		false)
}

// AfterApply validates flag combinations.
func (cmd *SetupCmd) AfterApply() error {
	if cmd.PIN != "" {
		if err := validatePIN(cmd.PIN); err != nil {
			return err
		}
	}
	if cmd.NewPIN != "" {
		if err := validatePIN(cmd.NewPIN); err != nil {
			return err
		}
	}

	if cmd.FactoryReset && cmd.PIN != "" {
		return fmt.Errorf("use --new-pin instead of --pin with --factory-reset")
	}

	if cmd.Force && cmd.NewPIN == "" {
		if cmd.FactoryReset {
			return fmt.Errorf("--new-pin required when using --force with --factory-reset")
		}
	}

	seenSigning := map[string]bool{}
	for _, policy := range cmd.SigningKeys {
		if seenSigning[policy] {
			return fmt.Errorf("duplicate touch policy specified in --signing-keys")
		}
		seenSigning[policy] = true
	}

	seenDecrypting := map[string]bool{}
	for _, policy := range cmd.DecryptingKeys {
		if seenDecrypting[policy] {
			return fmt.Errorf("duplicate touch policy specified in --decrypting-keys")
		}
		seenDecrypting[policy] = true
	}

	return nil
}

// Run the setup command to configure a security key.
func (cmd *SetupCmd) Run(l *slog.Logger) error {
	p := piv.New(l, pinentry.New("pinentry"))
	securityKeys, err := p.SecurityKeys()
	if err != nil {
		return fmt.Errorf("couldn't get security keys: %v", err)
	}

	var targetKey *securitykey.SecurityKey
	for _, k := range securityKeys {
		if cmd.Serial != 0 && k.Serial() != cmd.Serial {
			continue
		}
		if targetKey != nil {
			return fmt.Errorf(
				`multiple security keys matched: ` +
					`use "piv-agent status" to list all keys, ` +
					`and "piv-agent --serial=..." to select one`)
		}
		targetKey = k
	}
	if targetKey == nil {
		return fmt.Errorf("no matching security key found")
	}
	ff, err := targetKey.FormFactor()
	if err != nil {
		ff = "Unknown"
	}

	fmt.Println("Setting up security key:")
	printKeyStatus(targetKey, nil, false, false)

	isFactoryState, err := targetKey.IsFactoryState()
	if err != nil {
		return fmt.Errorf("couldn't check if key is in factory state: %v", err)
	}

	var signingKeys []string
	var decryptingKeys []string

	if len(cmd.SigningKeys) == 0 && len(cmd.DecryptingKeys) == 0 {
		if cmd.FactoryReset || isFactoryState {
			signingKeys = []string{"cached", "always", "never"}
			decryptingKeys = []string{"cached", "always", "never"}
		} else {
			return fmt.Errorf("security key is already set up: " +
				"configure specific slots with --signing-keys or --decrypting-keys, " +
				"or use --factory-reset")
		}
	} else {
		// specific key specified
		signingKeys = cmd.SigningKeys
		decryptingKeys = cmd.DecryptingKeys

		if !cmd.FactoryReset && !isFactoryState {
			ok, err := confirmOverwrite(targetKey, cmd.Force, signingKeys, decryptingKeys)
			if err != nil {
				return fmt.Errorf("couldn't confirm overwriting keys: %v", err)
			}
			if !ok {
				return fmt.Errorf("overwriting keys denied")
			}
		}
	}

	currentPIN := cmd.PIN
	newPIN := cmd.NewPIN

	switch {
	case cmd.FactoryReset:
		expectedPhrase := "YES, WIPE ALL KEYS ON THIS DEVICE"
		_, err := fmt.Printf(
			"\n⚠️ WARNING: This action will destroy any existing keys on the "+
				"%s (serial %d) device, and set a new PIN/PUK and management key ⚠️\n\n",
			ff,
			targetKey.Serial())
		if err != nil {
			return err
		}
		if cmd.Force {
			fmt.Println("Wiping keys on device without further prompts.")
		} else {
			ok, err := promptConfirm(
				fmt.Sprintf("To continue, type exactly:\n%s\n> ", expectedPhrase),
				expectedPhrase,
				true)
			if err != nil {
				return err // bare error: confirmation failed
			}
			if !ok {
				return fmt.Errorf("setup cancelled")
			}
			if cmd.NewPIN == "" {
				newPIN, err = promptPIN("Enter a new PIN/PUK (6-8 digits): ", true)
				if err != nil {
					return fmt.Errorf("couldn't get pin: %v", err)
				}
			}
		}
	case isFactoryState:
		// if currentPIN is empty (--pin not passed), SecurityKey.Setup() will fall
		// back to using the default PIN.
		expectedPhrase := "yes"
		_, err := fmt.Printf(
			"\nIt looks like the %s (serial %d) device is in default factory state. "+
				"Continuing will set the PIN/PUK and management key.\n",
			ff,
			targetKey.Serial())
		if err != nil {
			return err
		}
		if cmd.Force {
			if cmd.NewPIN == "" {
				return fmt.Errorf("--new-pin is required when using --force on a factory-state key")
			}
		} else {
			ok, err := promptConfirm(
				fmt.Sprintf("To continue, type:\n%s\n> ", expectedPhrase),
				expectedPhrase,
				false)
			if err != nil {
				return fmt.Errorf("couldn't prompt for confirmation: %v", err)
			}
			if !ok {
				return fmt.Errorf("setup cancelled")
			}
			if cmd.NewPIN == "" {
				newPIN, err = promptPIN("Enter a new PIN/PUK (6-8 digits): ", true)
				if err != nil {
					return fmt.Errorf("couldn't get pin: %v", err)
				}
			}
		}
	default:
		if cmd.Force {
			if currentPIN == "" {
				return fmt.Errorf("--pin is required when using --force for incremental setup")
			}
		} else {
			if currentPIN == "" {
				currentPIN, err = promptPIN("Enter PIN (6-8 digits): ", false)
				if err != nil {
					return fmt.Errorf("couldn't get pin: %v", err)
				}
			}
		}
	}

	err = targetKey.Setup(version, securitykey.SetupOptions{
		FactoryReset:   cmd.FactoryReset,
		IsFactoryState: isFactoryState,
		SigningKeys:    signingKeys,
		DecryptingKeys: decryptingKeys,
		PIN:            currentPIN,
		NewPIN:         newPIN,
	})
	if err != nil {
		return err
	}

	fmt.Printf("\n✅ Successfully configured %d slot(s).\n\n",
		len(signingKeys)+len(decryptingKeys))
	printKeyStatus(targetKey, nil, false, false)

	return nil
}
