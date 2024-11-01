package securitykey

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	pivgo "github.com/go-piv/piv-go/v2/piv"
)

// DecryptingKey is a cryptographic decrypting key on a hardware security
// device.
type DecryptingKey struct {
	CryptoKey
	PubPGP *packet.PublicKey
}

// decryptingKeys returns the decrypting keys available on the given yubikey.
func decryptingKeys(yk *pivgo.YubiKey) ([]DecryptingKey, error) {
	var decryptingKeys []DecryptingKey
	for _, s := range defaultDecryptSlots {
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
		decryptingKeys = append(decryptingKeys, DecryptingKey{
			CryptoKey: CryptoKey{
				Public:   pubKey,
				SlotSpec: s,
			},
			PubPGP: packet.NewECDSAPublicKey(cert.NotBefore,
				openpgpECDSAPublicKey(pubKey)),
		})
	}
	return decryptingKeys, nil
}
