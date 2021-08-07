package main

import (
	"fmt"
	"strings"

	"github.com/smlx/piv-agent/internal/keyservice/piv"
	"go.uber.org/zap"
)

// ListCmd represents the list command.
type ListCmd struct {
	KeyFormats []string `kong:"default='ssh',enum='ssh,gpg',help='Key formats to list (ssh, gpg)'"`
	PGPName    string   `kong:"default='piv-agent',help='Name set on synthesized PGP identities'"`
	PGPEmail   string   `kong:"default='noreply@example.com',help='Email set on synthesized PGP identities'"`
}

// Run the list command.
func (cmd *ListCmd) Run(l *zap.Logger) error {
	p := piv.New(l)
	securityKeys, err := p.SecurityKeys()
	if err != nil {
		return fmt.Errorf("couldn't get security keys: %w", err)
	}
	fmt.Println("Security keys (cards):")
	for _, k := range securityKeys {
		fmt.Println(k.Card())
	}
	keyformats := map[string]bool{}
	for _, f := range cmd.KeyFormats {
		keyformats[f] = true
	}
	if keyformats["ssh"] {
		fmt.Println("\nSSH keys:")
		for _, k := range securityKeys {
			for _, s := range k.StringsSSH() {
				fmt.Println(strings.TrimSpace(s))
			}
		}
	}
	if keyformats["gpg"] {
		fmt.Println("\nGPG keys:")
		for _, k := range securityKeys {
			ss, err := k.StringsGPG(cmd.PGPName, cmd.PGPEmail)
			if err != nil {
				return fmt.Errorf("couldn't get GPG keys as strings: %v", err)
			}
			for _, s := range ss {
				fmt.Println(s)
			}
		}
	}
	return nil
}
