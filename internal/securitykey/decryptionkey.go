package securitykey

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/openpgp/packet"
)

// DecryptionKey is a cryptographic decryption key on a hardware security
// device.
type DecryptionKey struct {
	CryptoKey
	PubPGP *packet.PublicKey
}

// decryptionKeys returns the decryption keys available on the given yubikey.
func decryptionKeys(yk *piv.YubiKey) ([]DecryptionKey, error) {
	var decryptionKeys []DecryptionKey
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
		decryptionKeys = append(decryptionKeys, DecryptionKey{
			CryptoKey: CryptoKey{
				Public:   pubKey,
				SlotSpec: s,
			},
			PubPGP: packet.NewECDSAPublicKey(cert.NotBefore, pubKey),
		})
	}
	return decryptionKeys, nil
}
