package gpg

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	"math/big"
)

type part struct {
	name  string
	value []byte
}

// KeygripECDSA calculates a keygrip for an ECDSA public key. This is a SHA1 hash of
// public key parameters. It is pretty much undocumented outside of the
// libgcrypt codebase.
//
// The idea behind the keygrip is to use only the cryptographic properties of
// the public key to produce an identifier. Each parameter (part) of the public
// key is byte-encoded, the parts are s-exp encoded in a particular order, and
// then the s-exp is sha1-hashed to produced the keygrip, which is generally
// displayed hex-encoded.
func KeygripECDSA(pubKey *ecdsa.PublicKey) ([]byte, error) {
	if pubKey == nil {
		return nil, fmt.Errorf("nil key")
	}
	// extract the p, a, b, g, n, an q parameters
	var p, a, b, g, gx, gy, n, q, x, y *big.Int

	p = pubKey.Params().P

	a = big.NewInt(-3)
	a.Mod(a, p)

	// we need to allocate and set rather than just assign here and throughout
	// the function otherwise we end up mutating the curve variable directly!
	b = big.NewInt(0)
	b.Set(pubKey.Params().B)
	b.Mod(b, p)

	g = big.NewInt(4)
	g.Lsh(g, 512)
	gx = big.NewInt(0)
	gx.Set(pubKey.Params().Gx)
	gx.Lsh(gx, 256)
	g.Or(g, gx)
	gy = big.NewInt(0)
	gy.Set(pubKey.Params().Gy)
	g.Or(g, gy)

	n = pubKey.Params().N

	q = big.NewInt(4)
	q.Lsh(q, 512)
	x = big.NewInt(0)
	x.Set(pubKey.X)
	x.Lsh(x, 256)
	q.Or(q, x)
	y = big.NewInt(0)
	y.Set(pubKey.Y)
	q.Or(q, y)

	parts := []part{
		{name: "p", value: p.Bytes()[:32]},
		{name: "a", value: a.Bytes()[:32]},
		{name: "b", value: b.Bytes()[:32]},
		{name: "g", value: g.Bytes()[:65]},
		{name: "n", value: n.Bytes()[:32]},
		{name: "q", value: q.Bytes()[:65]},
	}
	// hash them all
	return compute(parts)
}

func compute(parts []part) ([]byte, error) {
	h := new(bytes.Buffer)
	for i := 0; i < len(parts); i++ {
		_, err := fmt.Fprintf(h, "(%d:%s%d:%s)", len(parts[i].name), parts[i].name, len(parts[i].value), parts[i].value)
		if err != nil {
			return nil, err
		}
	}
	s := sha1.Sum(h.Bytes())
	return s[:], nil
}

// keygripRSA calculates a keygrip for an RSA public key.
func keygripRSA(pubKey *rsa.PublicKey) []byte {
	keygrip := sha1.New()
	keygrip.Write([]byte{0})
	keygrip.Write(pubKey.N.Bytes())
	return keygrip.Sum(nil)
}
