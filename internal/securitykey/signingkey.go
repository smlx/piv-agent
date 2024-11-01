package securitykey

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	pivgo "github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"
)

// SigningKey is a public signing key on a security key / hardware token.
type SigningKey struct {
	CryptoKey
	PubSSH ssh.PublicKey
	PubPGP *packet.PublicKey
}

// signingKeys returns the signing keys available on the given yubikey.
func signingKeys(yk *pivgo.YubiKey) ([]SigningKey, error) {
	var signingKeys []SigningKey
	for _, s := range defaultSignSlots {
		cert, err := yk.Certificate(s.Slot)
		if err != nil {
			if errors.Is(err, pivgo.ErrNotFound) {
				continue
			}
			return nil, fmt.Errorf("couldn't get certificate for slot %x: %v",
				s.Slot.Key, err)
		}
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid public key type: %T", cert.PublicKey)
		}
		pubSSH, err := ssh.NewPublicKey(cert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("couldn't convert public key: %v", err)
		}
		signingKeys = append(signingKeys, SigningKey{
			CryptoKey: CryptoKey{
				Public:   pubKey,
				SlotSpec: s,
			},
			PubSSH: pubSSH,
			PubPGP: packet.NewECDSAPublicKey(cert.NotBefore,
				openpgpECDSAPublicKey(pubKey)),
		})
	}
	return signingKeys, nil
}
