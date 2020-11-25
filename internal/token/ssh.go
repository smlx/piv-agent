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
	PublicKey   ssh.PublicKey
	KeySpec     KeySpec
	SecurityKey SecurityKey
}

// SSHKeySpecs returns all the SSHKeySpecs available on the given list of
// SecurityKeys.
func SSHKeySpecs(securityKeys []SecurityKey) ([]SSHKeySpec, error) {
	var pubKeys []SSHKeySpec
	for _, sk := range securityKeys {
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
				PublicKey:   pub,
				KeySpec:     keySpec,
				SecurityKey: sk,
			})
		}
	}
	return pubKeys, nil
}
