package token

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/ssh"
)

// SSHKeySpec represents an SSH key stored on a security key / hardware token.
type SSHKeySpec struct {
	PubKey      ssh.PublicKey
	Slot        piv.Slot
	TouchPolicy piv.TouchPolicy
	Card        string
	Serial      uint32
}

// SSHKeySpecs returns all the SSHKeySpecs available on the given list of
// SecurityKeys.
func SSHKeySpecs(sks []SecurityKey) ([]SSHKeySpec, error) {
	var pubKeys []SSHKeySpec
	for _, sk := range sks {
		for _, keySpec := range AllKeySpecs {
			cert, err := sk.Key.Certificate(keySpec.Slot)
			if err != nil {
				if errors.Is(err, piv.ErrNotFound) {
					continue
				}
				return nil, fmt.Errorf("couldn't get certificate for slot %x: %w",
					keySpec.Slot.Key, err)
			}
			_, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("invalid public key type: %T", cert.PublicKey)
			}
			pub, err := ssh.NewPublicKey(cert.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't convert public key: %w", err)
			}
			pubKeys = append(pubKeys, SSHKeySpec{
				PubKey:      pub,
				Slot:        keySpec.Slot,
				TouchPolicy: keySpec.TouchPolicy,
				Card:        sk.Card,
				Serial:      sk.Serial,
			})
		}
	}
	return pubKeys, nil
}
