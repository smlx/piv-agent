package assuan

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/smlx/piv-agent/internal/notify"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// sign performs signing of the specified "hash" data, using the specified
// "hashAlgo" hash algorithm. It then encodes the response into an s-expression
// and returns it as a byte slice.
func (a *Assuan) sign() ([]byte, error) {
	switch a.signer.Public().(type) {
	case *rsa.PublicKey:
		return a.signRSA()
	default:
		// default also handles mock signers in the test suite
		return a.signECDSA()
	}
}

// signRSA returns a signature for the given hash.
func (a *Assuan) signRSA() ([]byte, error) {
	signature, err := a.signer.Sign(rand.Reader, a.hash, a.hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("couldn't sign: %v", err)
	}
	return []byte(fmt.Sprintf(`D (7:sig-val(3:rsa(1:s%d:%s)))`, len(signature),
		percentEncodeSExp(signature))), nil
}

// signECDSA returns a signature for the given hash.
//
// This function's complexity is due to the fact that while Sign() returns the
// r and s components of the signature ASN1-encoded, gpg expects them to be
// separately s-exp encoded. So we have to decode the ASN1 signature, extract
// the params, and re-encode them into the s-exp. Ugh.
func (a *Assuan) signECDSA() ([]byte, error) {
	cancel := notify.Touch(nil)
	defer cancel()
	signature, err := a.signer.Sign(rand.Reader, a.hash, a.hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("couldn't sign: %v", err)
	}
	var sig cryptobyte.String = signature
	var b []byte
	if !sig.ReadASN1Bytes(&b, asn1.SEQUENCE) {
		return nil, fmt.Errorf("couldn't read asn1.SEQUENCE")
	}
	var rawInts cryptobyte.String = b
	var r, s big.Int
	if !rawInts.ReadASN1Integer(&r) {
		return nil, fmt.Errorf("couldn't read r as asn1.Integer")
	}
	if !rawInts.ReadASN1Integer(&s) {
		return nil, fmt.Errorf("couldn't read s as asn1.Integer")
	}
	// encode the params (r, s) into s-exp
	return []byte(fmt.Sprintf(`D (7:sig-val(5:ecdsa(1:r32#%X#)(1:s32#%X#)))`,
		r.Bytes(), s.Bytes())), nil
}
