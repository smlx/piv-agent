package securitykey

import (
	"crypto/ecdsa"

	openpgpecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
)

// openpgpECDSAPublicKey converts the given ECDSA Key in crypto/ecdsa
// representation, to go-crypto/openpgp representation.
func openpgpECDSAPublicKey(k *ecdsa.PublicKey) *openpgpecdsa.PublicKey {
	openpgpPubKey := openpgpecdsa.NewPublicKeyFromCurve(k.Curve)
	openpgpPubKey.X = k.X
	openpgpPubKey.Y = k.Y
	return openpgpPubKey
}
