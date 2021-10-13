package securitykey

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/openpgp/packet"
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
			PubPGP: packet.NewECDSAPublicKey(cert.NotBefore, pubKey),
		})
	}
	return decryptingKeys, nil
}
