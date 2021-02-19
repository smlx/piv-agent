package token

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/ssh"
)

// SigningKey represents a signing key on a security key / hardware token.
type SigningKey struct {
	PubSSH      ssh.PublicKey
	PubPGP      *packet.PublicKey
	Slot        piv.Slot
	TouchPolicy piv.TouchPolicy
	Card        string
	Serial      uint32
}

// SigningKeys returns the signing keys available on the given Tokens.
func SigningKeys(tokens []Token) ([]SigningKey, error) {
	var signingKeys []SigningKey
	for _, t := range tokens {
		for _, s := range SignSlotSpecs {
			cert, err := t.Key.Certificate(s.Slot)
			if err != nil {
				if errors.Is(err, piv.ErrNotFound) {
					continue
				}
				return nil, fmt.Errorf("couldn't get certificate for slot %x: %w",
					s.Slot.Key, err)
			}
			pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("invalid public key type: %T", cert.PublicKey)
			}
			pubSSH, err := ssh.NewPublicKey(cert.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't convert public key: %w", err)
			}
			signingKeys = append(signingKeys, SigningKey{
				PubSSH:      pubSSH,
				PubPGP:      packet.NewECDSAPublicKey(cert.NotBefore, pubKey),
				Slot:        s.Slot,
				TouchPolicy: s.TouchPolicy,
				Card:        t.Card,
				Serial:      t.Serial,
			})
		}
	}
	return signingKeys, nil
}
