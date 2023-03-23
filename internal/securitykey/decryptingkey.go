package securitykey

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	openpgpecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/go-piv/piv-go/piv"
)

// DecryptingKey is a cryptographic decrypting key on a hardware security
// device.
type DecryptingKey struct {
	CryptoKey
	PubPGP *packet.PublicKey
}

// decryptingKeys returns the decrypting keys available on the given yubikey.
func decryptingKeys(yk *piv.YubiKey) ([]DecryptingKey, error) {
	var decryptingKeys []DecryptingKey
	for _, s := range defaultDecryptSlots {
		cert, err := yk.Certificate(s.Slot)
		if err != nil {
			if errors.Is(err, piv.ErrNotFound) {
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
				openpgpecdsa.NewPublicKeyFromCurve(pubKey.Curve)),
		})
	}
	return decryptingKeys, nil
}
