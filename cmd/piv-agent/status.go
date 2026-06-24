package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/smlx/piv-agent/internal/pinentry"
	"github.com/smlx/piv-agent/internal/piv"
	"github.com/smlx/piv-agent/internal/securitykey"
)

// StatusCmd represents the status command.
type StatusCmd struct {
	SigningKeys     []string `kong:"enum='cached,always,never',help='Filter by signing keys with various touch policies'"`
	DecryptingSlots []string `kong:"help='Filter by decrypting slots (e.g., 82, 83)'"`
	AgeRecipients   bool     `kong:"help='Omit the identity and only print the age recipient for the specified slot',xor='age'"`
	AgeIdentities   bool     `kong:"help='Only print the age identities for the specified slot',xor='age'"`
}

// printKeyStatus prints the status of the provided security key.
// If slotFilter is non-empty, it limits the status output to that specific
// slot. If ageRecipients is true, it only prints the age recipient strings.
// If ageIdentities is true, it only prints the age identities.
func printKeyStatus(
	k *securitykey.SecurityKey,
	slotFilter []uint32,
	ageRecipients,
	ageIdentities bool,
) {
	if ageRecipients {
		ageKeys, err := k.StringsAge(slotFilter)
		if err == nil {
			for _, s := range ageKeys {
				if recipient, ok := strings.CutPrefix(s, "# Recipient: "); ok {
					fmt.Println(recipient)
				}
			}
		}
		return
	}

	if ageIdentities {
		ageKeys, err := k.StringsAge(slotFilter)
		if err == nil {
			for _, s := range ageKeys {
				fmt.Println(s)
			}
		}
		return
	}

	ff, err := k.FormFactor()
	if err != nil {
		ff = "Unknown"
	}
	fmt.Printf("%s (Serial %d, %s, Firmware v%s)\n",
		k.Card(), k.Serial(), ff, k.Version())
	reports := k.Statuses(slotFilter)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()
	var symbol string
	var desc string
	var missingSeed bool
	var hasLocalSeed bool
	for _, r := range reports {
		switch r.Status {
		case securitykey.SlotStatusPivAgent:
			symbol = "🟢"
			desc = "Set up by piv-agent"
			if r.Type == securitykey.SlotTypeDecrypting {
				hasLocalSeed = true
			}
		case securitykey.SlotStatusCompatible:
			symbol = "🔵"
			desc = "Compatible key"
		case securitykey.SlotStatusNotSetup:
			symbol = "⚪"
			desc = "Not set up"
		case securitykey.SlotStatusIncompatible:
			symbol = "🔴"
			desc = "Incompatible key"
		case securitykey.SlotStatusMissingSeed:
			symbol = "🟡"
			desc = "Missing local seed"
			missingSeed = true
		}
		rStr := fmt.Sprintf("Slot %x\t(%s,\ttouch policy: %s)",
			r.Slot.Key, r.Type.String(), securitykey.TouchPolicyString(r.TouchPolicy))
		if r.Error != nil {
			fmt.Fprintf(w, "\t%s\t%s\t%s\t(%s)\n", symbol, rStr, desc, r.Error)
		} else {
			fmt.Fprintf(w, "\t%s\t%s\t%s\t\n", symbol, rStr, desc)
		}
	}

	sshKeys, err := k.StringsSSH()
	if err != nil {
		fmt.Printf("Couldn't get SSH strings: %v\n", err)
	}
	if len(sshKeys) > 0 {
		fmt.Fprintf(w, "\n\tSSH keys:\n")
		for _, s := range sshKeys {
			fmt.Fprintf(w, "\t%s\n", strings.TrimSpace(s))
		}
	}

	ageKeys, err := k.StringsAge(slotFilter)
	var nonFatal securitykey.NonFatalErrors
	if err != nil && !errors.As(err, &nonFatal) {
		fmt.Fprintf(w, "\n\tCouldn't get age identities as strings: %v\n", err)
		return
	}

	if len(ageKeys) > 0 {
		fmt.Fprintf(w, "\n\tAge identities:\n")
		for _, s := range ageKeys {
			if s == "" {
				fmt.Fprintln(w)
			} else {
				fmt.Fprintf(w, "\t%s\n", s)
			}
		}
	}

	if len(nonFatal) > 0 {
		fmt.Fprintf(w, "\n\tAge identities errors:\n")
		for _, e := range nonFatal {
			fmt.Fprintf(w, "\t- %v\n", e)
		}
	}

	if missingSeed && !hasLocalSeed {
		fmt.Fprintf(w, "\n\t⚠️  Missing local seed: A slot is configured on the hardware, but its required\n")
		fmt.Fprintf(w, "\t    ML-KEM seed is not available on this machine. It cannot be used for decryption here.\n")
		fmt.Fprintf(w, "\t    Run 'piv-agent setup --add-decrypting-key' to provision a new identity for this host.\n")
	}
}

// Run the status command.
func (cmd *StatusCmd) Run(l *slog.Logger) error {
	p := piv.New(l, pinentry.New("pinentry"))
	securityKeys, err := p.SecurityKeys()
	if err != nil {
		return fmt.Errorf("couldn't get security keys: %v", err)
	}

	var slotFilter []uint32

	for _, policy := range cmd.SigningKeys {
		s, err := securitykey.SigningSlotSpec(policy)
		if err != nil {
			return err
		}
		slotFilter = append(slotFilter, s.Slot.Key)
	}

	for _, slotHex := range cmd.DecryptingSlots {
		cleanSlotHex := strings.TrimPrefix(strings.ToLower(slotHex), "0x")
		var slotKey uint32
		_, err := fmt.Sscanf(cleanSlotHex, "%x", &slotKey)
		if err != nil {
			return fmt.Errorf("invalid decrypting slot hex %q: %v", slotHex, err)
		}
		slotFilter = append(slotFilter, slotKey)
	}

	for i, k := range securityKeys {
		if i > 0 && !cmd.AgeRecipients && !cmd.AgeIdentities {
			fmt.Println()
		}
		printKeyStatus(k, slotFilter, cmd.AgeRecipients, cmd.AgeIdentities)
	}

	return nil
}
