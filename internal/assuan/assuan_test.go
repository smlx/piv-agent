package assuan_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/smlx/piv-agent/internal/assuan"
	"github.com/smlx/piv-agent/internal/mock"
	"github.com/smlx/piv-agent/internal/pivservice"
	"github.com/smlx/piv-agent/internal/securitykey"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// MockCryptoSigner is a mock type which implements crypto.Signer
type MockCryptoSigner struct {
	PubKey    crypto.PublicKey
	Signature []byte
}

func (s *MockCryptoSigner) Public() crypto.PublicKey {
	return s.PubKey
}

func (s *MockCryptoSigner) Sign(_ io.Reader, _ []byte,
	_ crypto.SignerOpts) ([]byte, error) {
	return s.Signature, nil
}

func TestSign(t *testing.T) {
	var testCases = map[string]struct {
		keyPath string
		input   []string
		expect  []string
	}{
		// test data is taken from a successful signing by gpg-agent
		"sign file": {
			keyPath: "testdata/C54A8868468BC138.asc",
			input: []string{
				"RESET\n",
				"OPTION ttyname=/dev/pts/8\n",
				"OPTION ttytype=xterm-256color\n",
				"OPTION display=:0\n",
				"OPTION xauthority=/run/user/1000/.mutter-Xwaylandauth.HH1R00\n",
				"OPTION putenv=XMODIFIERS=@im=ibus\n",
				"OPTION putenv=WAYLAND_DISPLAY=wayland-0\n",
				"OPTION putenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus\n",
				"OPTION putenv=QT_IM_MODULE=ibus\n",
				"OPTION lc-ctype=en_AU.UTF-8\n",
				"OPTION lc-messages=en_AU.UTF-8\n",
				"GETINFO version\n",
				"OPTION allow-pinentry-notify\n",
				"OPTION agent-awareness=2.1.0\n",
				"HAVEKEY 38F053358EFD6C923D08EE4FC4CEB208CBCDF73C\n",
				"RESET\n",
				"SIGKEY 38F053358EFD6C923D08EE4FC4CEB208CBCDF73C\n",
				"SETKEYDESC Please+enter+the+passphrase+to+unlock+the+OpenPGP+secret+key:%0A%22foo+bar+<foo@example.com>%22%0A256-bit+ECDSA+key,+ID+0xC54A8868468BC138,%0Acreated+2021-03-20.%0A\n",
				"SETHASH 8 7F05E3237420D1AAA74A4B96D6E5CD01715CB26487661209192684A8EF232B90\n",
				"PKSIGN\n",
			},
			expect: []string{
				"OK Pleased to meet you, process 123456789\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"D 2.2.27\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"D (7:sig-val(5:ecdsa(1:r32#2eeba51cc802edf6acf44cb6b2506bfeda8727cf9f623939420bccd02f2c1b89#)(1:s32#8a3d09e0a2fed86802d6c6e2a429ff97f98b5fc9880442745c6d2f4557104070#)))\n",
				"OK\n",
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			// load key test fixture
			pubKey, err := ecdsaPubKeyLoad(tc.keyPath)
			if err != nil {
				tt.Fatal(err)
			}
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			r := big.NewInt(0).SetBytes([]byte("\x2e\xeb\xa5\x1c\xc8\x02\xed\xf6\xac\xf4\x4c\xb6\xb2\x50\x6b\xfe\xda\x87\x27\xcf\x9f\x62\x39\x39\x42\x0b\xcc\xd0\x2f\x2c\x1b\x89"))
			s := big.NewInt(0).SetBytes([]byte("\x8a\x3d\x09\xe0\xa2\xfe\xd8\x68\x02\xd6\xc6\xe2\xa4\x29\xff\x97\xf9\x8b\x5f\xc9\x88\x04\x42\x74\x5c\x6d\x2f\x45\x57\x10\x40\x70"))
			// this snippet is taken from ecdsa.Sign()
			var b cryptobyte.Builder
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1BigInt(r)
				b.AddASN1BigInt(s)
			})
			signature, err := b.Bytes()
			if err != nil {
				tt.Fatal(err)
			}
			var mockSecurityKey = mock.NewMockSecurityKey(ctrl)
			mockSecurityKey.EXPECT().PrivateKey(gomock.Any()).Return(&MockCryptoSigner{
				PubKey:    pubKey,
				Signature: signature,
			}, nil)
			mockSecurityKey.EXPECT().SigningKeys().AnyTimes().Return(
				[]securitykey.SigningKey{{Public: pubKey}})
			pivService := mock.NewMockPIVService(ctrl)
			pivService.EXPECT().SecurityKeys().AnyTimes().Return(
				[]pivservice.SecurityKey{mockSecurityKey}, nil)
			// writeBuf is the buffer that the assuan statemachine writes to
			writeBuf := bytes.Buffer{}
			// readBuf is the buffer that the assuan statemachine reads from
			readBuf := bytes.Buffer{}
			a := assuan.New(&writeBuf, pivService)
			// write all the lines into the statemachine
			for _, in := range tc.input {
				if _, err := readBuf.WriteString(in); err != nil {
					tt.Fatal(err)
				}
			}
			// start the state machine
			if err := a.Run(&readBuf); err != nil {
				tt.Fatal(err)
			}
			// check the responses
			for _, expected := range tc.expect {
				line, err := writeBuf.ReadString(byte('\n'))
				if err != nil && err != io.EOF {
					tt.Fatal(err)
				}
				if line != expected {
					tt.Fatalf(`got %#v, expected %#v`, line, expected)
				}
			}
		})
	}
}

func TestKeyinfo(t *testing.T) {
	var testCases = map[string]struct {
		keyPath string
		input   []string
		expect  []string
	}{
		"keyinfo": {
			keyPath: "testdata/C54A8868468BC138.asc",
			input: []string{
				"RESET\n",
				"KEYINFO 38F053358EFD6C923D08EE4FC4CEB208CBCDF73C\n",
			},
			expect: []string{
				"OK Pleased to meet you, process 123456789\n",
				"OK\n",
				"S KEYINFO 38F053358EFD6C923D08EE4FC4CEB208CBCDF73C D - - - P - - -\n",
				"OK\n",
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			// load key test fixture
			pubKey, err := ecdsaPubKeyLoad(tc.keyPath)
			if err != nil {
				tt.Fatal(err)
			}
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			var mockSecurityKey = mock.NewMockSecurityKey(ctrl)
			mockSecurityKey.EXPECT().SigningKeys().AnyTimes().Return(
				[]securitykey.SigningKey{{Public: pubKey}})
			pivService := mock.NewMockPIVService(ctrl)
			pivService.EXPECT().SecurityKeys().AnyTimes().Return(
				[]pivservice.SecurityKey{mockSecurityKey}, nil)
			// writeBuf is the buffer that the assuan statemachine writes to
			writeBuf := bytes.Buffer{}
			// readBuf is the buffer that the assuan statemachine reads from
			readBuf := bytes.Buffer{}
			a := assuan.New(&writeBuf, pivService)
			// write all the lines into the statemachine
			for _, in := range tc.input {
				if _, err := readBuf.WriteString(in); err != nil {
					tt.Fatal(err)
				}
			}
			// start the state machine
			if err := a.Run(&readBuf); err != nil {
				tt.Fatal(err)
			}
			// check the responses
			for _, expected := range tc.expect {
				line, err := writeBuf.ReadString(byte('\n'))
				if err != nil && err != io.EOF {
					tt.Fatal(err)
				}
				if line != expected {
					tt.Fatalf(`got %#v, expected %#v`, line, expected)
				}
			}
		})
	}
}

func ecdsaPubKeyLoad(path string) (*ecdsa.PublicKey, error) {
	in, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("couldn't open file: %v", err)
	}
	defer in.Close()
	block, err := armor.Decode(in)
	if err != nil {
		return nil, fmt.Errorf("couldn't load ascii key %v", err)
	}
	if block.Type != openpgp.PublicKeyType {
		return nil, fmt.Errorf("invalid block type")
	}
	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		return nil, fmt.Errorf("couldn't get next packet: %v", err)
	}
	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an openpgp public key")
	}
	eccKey, ok := key.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ecdsa public key")
	}
	return eccKey, nil
}
