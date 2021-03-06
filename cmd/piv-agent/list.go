package main

import (
	"fmt"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/smlx/piv-agent/internal/token"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// ListCmd represents the list command.
type ListCmd struct{}

var touchStringMap = map[piv.TouchPolicy]string{
	piv.TouchPolicyNever:  "never",
	piv.TouchPolicyAlways: "always",
	piv.TouchPolicyCached: "cached",
}

// Run the list command.
func (cmd *ListCmd) Run(log *zap.Logger) error {
	securityKeys, err := token.List(log)
	if err != nil {
		return fmt.Errorf("couldn't get security keys: %w", err)
	}
	fmt.Println("security keys (cards):")
	for _, sk := range securityKeys {
		fmt.Println(sk.Card)
	}
	sshKeySpecs, err := token.SSHKeySpecs(securityKeys)
	if err != nil {
		return fmt.Errorf("couldn't get SSH public keys: %w", err)
	}
	fmt.Println("ssh keys:")
	for _, sks := range sshKeySpecs {
		fmt.Printf("%s %s\n",
			strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(sks.PubKey)), "\n"),
			fmt.Sprintf("%v #%v, touch policy: %s",
				sks.Card,
				sks.Serial,
				touchStringMap[sks.TouchPolicy]))
	}
	return nil
}
