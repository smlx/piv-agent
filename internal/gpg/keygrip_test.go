package gpg_test

import (
	"crypto/ecdsa"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/smlx/piv-agent/internal/gpg"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func TestKeyGrip(t *testing.T) {
	var testCases = map[string]struct {
		input  string
		expect string
	}{
		"keygrip 1": {input: "testdata/key1.asc", expect: "27B6858AA86F7B3DE9ADF89D5C91EA06558659DE"},
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
			key, ok := pkt.(*packet.PublicKey)
			if !ok {
				tt.Fatal("not an openpgp public key")
			}
			eccKey, ok := key.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				tt.Fatal("not an ecdsa public key")
			}

			keygrip, err := gpg.Keygrip(eccKey)
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
