package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"

	"github.com/smlx/piv-agent/internal/pinentry"
	"github.com/smlx/piv-agent/internal/piv"
	"github.com/smlx/piv-agent/internal/securitykey"
	"golang.org/x/term"
)

// SetupCmd represents the setup command.
type SetupCmd struct {
	Serial           uint32   `kong:"help='Specify the serial number of the security key to target'"`
	FactoryReset     bool     `kong:"help='Wipe all existing keys on the security key and perform a full reset of the PIV applet'"`
	Force            bool     `kong:"help='Bypass all interactive confirmation prompts'"`
	PIN              string   `kong:"xor='pin',help='Authenticate with this PIN. Prompted interactively if not provided.'"`
	NewPIN           string   `kong:"xor='pin',help='Set this as the new PIN/PUK during factory reset or initial setup. Prompted interactively if not provided.'"`
	SigningKeys      []string `kong:"enum='cached,always,never',help='Generate signing keys with various touch policies'"`
	AddDecryptingKey bool     `kong:"help='Generate a new decrypting key on the next available hardware slot'"`
	OverwriteSlot    string   `kong:"help='Force setup of a specific slot (e.g. 82 or 9c)'"`
	TouchPolicy      string   `kong:"enum='cached,always,never',default='always',help='Touch policy to apply when using --overwrite-slot'"`
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
func promptConfirm(
	prompt,
	expectedPhrase string,
	caseSensitive bool,
) (bool, error) {
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
func confirmOverwrite(
	k *securitykey.SecurityKey,
	force bool,
	signingKeys []string,
	overwriteSlot string,
) (bool, error) {
	statuses := k.Statuses(nil)
	var slots []string
	for _, status := range statuses {
		// skip slots that the user isn't trying to configure
		slotOverwrite := false
		if status.Type == securitykey.SlotTypeSigning &&
			slices.Contains(signingKeys, securitykey.TouchPolicyString(status.TouchPolicy)) {
			slotOverwrite = true
		}
		cleanSlot := strings.TrimPrefix(strings.ToLower(overwriteSlot), "0x")
		if status.Type == securitykey.SlotTypeDecrypting &&
			cleanSlot != "" && fmt.Sprintf("%x", status.Slot.Key) == cleanSlot {
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

	if cmd.OverwriteSlot != "" {
		if cmd.AddDecryptingKey || len(cmd.SigningKeys) > 0 {
			return fmt.Errorf("--overwrite-slot cannot be used with --signing-keys or --add-decrypting-key")
		}
	}
	if cmd.OverwriteSlot == "" && cmd.TouchPolicy != "always" {
		return fmt.Errorf("--touch-policy can only be used with --overwrite-slot")
	}

	seenSigning := map[string]bool{}
	for _, policy := range cmd.SigningKeys {
		if seenSigning[policy] {
			return fmt.Errorf("duplicate touch policy specified in --signing-keys")
		}
		seenSigning[policy] = true
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
	var addDecryptingKey bool
	var overwriteSlot string
	var touchPolicy string

	if len(cmd.SigningKeys) == 0 && !cmd.AddDecryptingKey && cmd.OverwriteSlot == "" {
		if cmd.FactoryReset || isFactoryState {
			signingKeys = []string{"cached", "always", "never"}
			addDecryptingKey = true
		} else {
			return fmt.Errorf("security key is already set up: " +
				"configure specific slots with --signing-keys, --add-decrypting-key, or --overwrite-slot, " +
				"or use --factory-reset")
		}
	} else {
		// specific key specified
		signingKeys = cmd.SigningKeys
		addDecryptingKey = cmd.AddDecryptingKey
		overwriteSlot = cmd.OverwriteSlot
		touchPolicy = cmd.TouchPolicy

		if len(signingKeys) > 0 || addDecryptingKey || overwriteSlot != "" {
			fmt.Printf("\nConfiguration to be applied:\n")
			for _, p := range signingKeys {
				if spec, err := securitykey.SigningSlotSpec(p); err == nil {
					fmt.Printf(" - Setup Signing slot %x with touch policy: %s\n", spec.Slot.Key, p)
				}
			}
			if addDecryptingKey {
				if spec, err := targetKey.NextAvailableDecryptSlot(); err == nil {
					fmt.Printf(" - Setup Decrypting slot %x with touch policy: always\n", spec.Slot.Key)
				} else {
					fmt.Printf(" - Setup Decrypting slot: (error finding next available slot)\n")
				}
			}
			if overwriteSlot != "" {
				fmt.Printf(" - Overwrite slot %s with touch policy: %s\n", overwriteSlot, touchPolicy)
			}
		}

		if !cmd.FactoryReset && !isFactoryState {
			ok, err := confirmOverwrite(targetKey, cmd.Force, signingKeys, overwriteSlot)
			if err != nil {
				return fmt.Errorf("couldn't confirm overwriting keys: %v", err)
			}
			if !ok {
				return fmt.Errorf("overwriting keys denied")
			}

			if addDecryptingKey && !cmd.Force {
				var hasAvailableSeed bool
				for _, status := range targetKey.Statuses(nil) {
					if status.Type == securitykey.SlotTypeDecrypting && status.Status == securitykey.SlotStatusPivAgent {
						hasAvailableSeed = true
						break
					}
				}
				if hasAvailableSeed {
					fmt.Printf("\n⚠️ WARNING: A decrypting slot is already configured and available for this machine. ⚠️\n")
					fmt.Printf("Adding another decrypting key will consume an additional slot.\n")
					ok, err := promptConfirm("Type \"yes\" to continue, or anything else to cancel: ", "yes", false)
					if err != nil {
						return fmt.Errorf("couldn't confirm adding decrypting key: %v", err)
					}
					if !ok {
						return fmt.Errorf("adding decrypting key denied")
					}
				}
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
		FactoryReset:     cmd.FactoryReset,
		IsFactoryState:   isFactoryState,
		SigningKeys:      signingKeys,
		AddDecryptingKey: addDecryptingKey,
		OverwriteSlot:    overwriteSlot,
		TouchPolicy:      touchPolicy,
		PIN:              currentPIN,
		NewPIN:           newPIN,
	})
	if err != nil {
		return err
	}

	numSlots := len(signingKeys)
	if addDecryptingKey || overwriteSlot != "" {
		numSlots++
	}
	fmt.Printf("\n✅ Successfully configured %d slot(s).\n\n", numSlots)
	printKeyStatus(targetKey, nil, false, false)

	return nil
}
