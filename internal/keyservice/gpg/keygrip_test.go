package gpg_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/smlx/piv-agent/internal/keyservice/gpg"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func TestTrezorCompat(t *testing.T) {
	var testCases = map[string]struct {
		input  *big.Int
		expect string
	}{
		"keygrip 1": {input: big.NewInt(1), expect: "95852E917FE2C39152BA998192B5791DB15CDCF0"},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {

			// construct private key
			priv := ecdsa.PrivateKey{}
			curve := elliptic.P256()
			priv.PublicKey.Curve = curve
			priv.D = tc.input
			priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(tc.input.Bytes())

			keygrip, err := gpg.KeygripECDSA(&priv.PublicKey)
			if err != nil {
				tt.Fatal(err)
			}
			kgString := strings.ToUpper(hex.EncodeToString(keygrip))
			if kgString != tc.expect {
				tt.Fatalf("expected %s, got %s", tc.expect, kgString)
			}
		})
	}
}

func TestKeyGrip(t *testing.T) {
	var testCases = map[string]struct {
		input  string
		expect string
	}{
		"keygrip 1": {input: "testdata/key1.asc", expect: "27B6858AA86F7B3DE9ADF89D5C91EA06558659DE"},
		"keygrip 2": {input: "testdata/key2.asc", expect: "D88F095C9279EE30E5F64AE82C0033A4CAE9D336"},
		"keygrip 3": {input: "testdata/key3.asc", expect: "137770C017D7693C1DAD922EB3E83AEFCC9743BA"},
		"keygrip 4": {input: "testdata/key4.asc", expect: "E21BD507D4B1C5E82858F69BC1C12D4E51EED503"},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {

			// parse ascii armored public key
			in, err := os.Open(tc.input)
			if err != nil {
				tt.Fatal(err)
			}
			defer in.Close()

			block, err := armor.Decode(in)
			if err != nil {
				tt.Fatal(err)
			}

			if block.Type != openpgp.PublicKeyType {
				tt.Fatal(err)
			}

			reader := packet.NewReader(block.Body)
			pkt, err := reader.Next()
			if err != nil {
				tt.Fatal(err)
			}
			key, ok := pkt.(*packet.PublicKey)
			if !ok {
				tt.Fatal("not an openpgp public key")
			}
			eccKey, ok := key.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				tt.Fatal("not an ecdsa public key")
			}
			if eccKey.Curve != elliptic.P256() {
				tt.Fatal("wrong curve")
			}

			keygrip, err := gpg.KeygripECDSA(eccKey)
			if err != nil {
				tt.Fatal(err)
			}
			kgString := strings.ToUpper(hex.EncodeToString(keygrip))
			if kgString != tc.expect {
				tt.Fatalf("expected %s, got %s", tc.expect, kgString)
			}
		})
	}
}
