package gpg

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
)

// HaveKey takes a list of keygrips, and returns a boolean indicating if any of
// the given keygrips were found, the found keygrip, and an error, if any.
func (g *KeyService) HaveKey(keygrips [][]byte) (bool, []byte, error) {
	for _, keyfile := range g.privKeys {
		for _, privKey := range keyfile.keys {
			pubKeyRSA, ok := privKey.PublicKey.PublicKey.(*rsa.PublicKey)
			if ok {
				for _, kg := range keygrips {
					rsaKG, err := keygripRSA(pubKeyRSA)
					if err != nil {
						return false, nil, err
					}
					if bytes.Equal(kg, rsaKG) {
						return true, kg, nil
					}
				}
			}
			pubKeyECDSA, ok := privKey.PublicKey.PublicKey.(*ecdsa.PublicKey)
			if ok {
				for _, kg := range keygrips {
					ecdsaKG, err := KeygripECDSA(pubKeyECDSA)
					if err != nil {
						return false, nil, err
					}
					if bytes.Equal(kg, ecdsaKG) {
						return true, kg, nil
					}
				}
			}
		}
	}
	return false, nil, nil
}
