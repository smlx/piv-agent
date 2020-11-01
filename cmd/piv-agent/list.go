package main

import (
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// ListCmd represents the list command.
type ListCmd struct{}

// Run the list command.
func (cmd *ListCmd) Run() error {
	log, err := zap.NewDevelopment()
	if err != nil {
		return fmt.Errorf("couldn't init logger: %w", err)
	}
	defer log.Sync()
	sks, err := getAllSecurityKeys(log)
	if err != nil {
		return fmt.Errorf("couldn't get security keys: %w", err)
	}
	pubKeySpecs, err := getSSHPubKeys(sks)
	if err != nil {
		return fmt.Errorf("couldn't get SSH public keys: %w", err)
	}
	for _, pks := range pubKeySpecs {
		fmt.Printf("🔑 %v #%v, touch policy: %s\n",
			pks.card,
			pks.serial,
			touchStringMap[pks.touchPolicy])
		fmt.Printf(string(ssh.MarshalAuthorizedKey(pks.pubKey)))
	}
	return nil
}
