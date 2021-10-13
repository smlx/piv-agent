package gpg

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
)

// Keygrips returns a slice of keygrip byteslices; one for each cryptographic
// key available on the keyservice.
func (g *KeyService) Keygrips() ([][]byte, error) {
	var grips [][]byte
	var kg []byte
	var err error
	for _, keyfile := range g.privKeys {
		for _, privKey := range keyfile.keys {
			switch pubKey := privKey.PublicKey.PublicKey.(type) {
			case *rsa.PublicKey:
				kg, err = keygripRSA(pubKey)
				if err != nil {
					return nil, fmt.Errorf("couldn't get keygrip: %w", err)
				}
			case *ecdsa.PublicKey:
				kg, err = KeygripECDSA(pubKey)
				if err != nil {
					return nil, fmt.Errorf("couldn't get keygrip: %w", err)
				}
			default:
				// unknown public key type
				continue
			}
			grips = append(grips, kg)
		}
	}
	return grips, nil
}

// HaveKey takes a list of keygrips, and returns a boolean indicating if any of
// the given keygrips were found, the found keygrip, and an error, if any.
func (g *KeyService) HaveKey(keygrips [][]byte) (bool, []byte, error) {
	for _, keyfile := range g.privKeys {
		for _, privKey := range keyfile.keys {
			switch pubKey := privKey.PublicKey.PublicKey.(type) {
			case *rsa.PublicKey:
				for _, kg := range keygrips {
					rsaKG, err := keygripRSA(pubKey)
					if err != nil {
						return false, nil, err
					}
					if bytes.Equal(kg, rsaKG) {
						return true, kg, nil
					}
				}
			case *ecdsa.PublicKey:
				for _, kg := range keygrips {
					ecdsaKG, err := KeygripECDSA(pubKey)
					if err != nil {
						return false, nil, err
					}
					if bytes.Equal(kg, ecdsaKG) {
						return true, kg, nil
					}
				}
			default:
				// unknown public key type
				continue
			}
		}
	}
	return false, nil, nil
}
