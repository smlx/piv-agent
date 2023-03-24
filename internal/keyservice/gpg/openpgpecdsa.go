package gpg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	openpgpecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
)

// nameToCurve takes a given curve name and returns the associated
// elliptic.Curve.
func nameToCurve(name string) (elliptic.Curve, error) {
	switch name {
	case elliptic.P224().Params().Name:
		return elliptic.P224(), nil
	case elliptic.P256().Params().Name:
		return elliptic.P256(), nil
	case elliptic.P384().Params().Name:
		return elliptic.P384(), nil
	case elliptic.P521().Params().Name:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unknown curve name: %s", name)
	}
}

// ecdsaPublicKey converts the given ECDSA Key in go-crypto/openpgp
// representation, to standard library crypto/ecdsa representation.
func ecdsaPublicKey(k *openpgpecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	curve, err := nameToCurve(k.GetCurve().GetCurveName())
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     k.X,
		Y:     k.Y,
	}, nil
}

// ecdsaPrivateKey converts the given ECDSA Key in go-crypto/openpgp
// representation, to standard library crypto/ecdsa representation.
func ecdsaPrivateKey(k *openpgpecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	curve, err := nameToCurve(k.GetCurve().GetCurveName())
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{
		D: k.D,
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     k.X,
			Y:     k.Y,
		},
	}, nil
}
