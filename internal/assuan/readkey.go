package assuan

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
)

// readKeyData returns information about the given key in a libgcrypt-specific
// format
func readKeyData(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		n := k.N.Bytes()
		nLen := len(n)           // need the actual byte length before munging
		n = PercentEncodeSExp(n) // ugh
		ei := new(big.Int)
		ei.SetInt64(int64(k.E))
		e := ei.Bytes()
		// prefix the key with a null byte for compatibility
		return fmt.Sprintf("D (10:public-key(3:rsa(1:n%d:\x00%s)(1:e%d:%s)))\nOK\n",
			nLen+1, n, len(e), e), nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			ecdhPubKey, err := k.ECDH()
			if err != nil {
				return "", fmt.Errorf("couldn't convert pub key to ecdh.PublicKey: %v", err)
			}
			q := ecdhPubKey.Bytes()
			qLen := len(q)
			q = PercentEncodeSExp(q)
			return fmt.Sprintf(
				"D (10:public-key(3:ecc(5:curve10:NIST P-256)(1:q%d:%s)))\nOK\n",
				qLen, q), nil
		default:
			return "", fmt.Errorf("unsupported curve: %T", k.Curve)
		}
	default:
		return "", nil
	}
}
