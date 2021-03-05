package gpg

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha1"
	"fmt"
	"math/big"

	"github.com/davecgh/go-spew/spew"
)

type part struct {
	name  string
	value []byte
}

// Keygrip calculates a keygrip for an ECDSA public key. This is a SHA1 hash of
// public key parameters. It is pretty much undocumented outside of the
// libgcrypt codebase.
func Keygrip(pubKey *ecdsa.PublicKey) ([]byte, error) {
	if pubKey == nil {
		return nil, fmt.Errorf("nil key")
	}
	// extract the p, a, b, g, n, an q parameters
	var p, a, b, g, gx, gy, n, q, x, y *big.Int

	p = pubKey.Params().P

	a = big.NewInt(-3)
	a.Mod(a, p)

	b = pubKey.Params().B
	b.Mod(b, p)

	g = big.NewInt(4)
	g.Lsh(g, 512)
	gx = pubKey.Params().Gx
	gx.Lsh(gx, 256)
	g.Or(g, gx)
	gy = pubKey.Params().Gy
	g.Or(g, gy)

	n = pubKey.Params().N

	q = big.NewInt(4)
	q.Lsh(g, 512)
	x = pubKey.X
	x.Lsh(x, 256)
	q.Or(q, x)
	y = pubKey.Y
	q.Or(q, y)

	parts := []part{
		{name: "p", value: p.Bytes()[:32]},
		{name: "a", value: a.Bytes()[:32]},
		{name: "b", value: b.Bytes()[:32]},
		{name: "g", value: g.Bytes()[:65]},
		{name: "n", value: n.Bytes()[:32]},
		{name: "q", value: q.Bytes()[:65]},
	}
	spew.Dump(parts)
	// hash them all
	return compute(parts)
}

func bigInt2Bytes(i *big.Int, n uint) []byte {
	buf := i.Bytes()
	return buf[:n]
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
