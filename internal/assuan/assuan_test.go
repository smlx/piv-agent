package assuan_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/davecgh/go-spew/spew"
	"github.com/smlx/piv-agent/internal/assuan"
	"github.com/smlx/piv-agent/internal/keyservice/gpg"
	"github.com/smlx/piv-agent/internal/mock"
	"github.com/smlx/piv-agent/internal/notify"
	"github.com/smlx/piv-agent/internal/securitykey"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// MockCryptoSigner is a mock type which implements crypto.Signer
type MockCryptoSigner struct {
	PubKey    *ecdsa.PublicKey
	Signature []byte
}

func (s *MockCryptoSigner) Public() crypto.PublicKey {
	return s.PubKey
}

func (s *MockCryptoSigner) Sign(_ io.Reader, _ []byte,
	_ crypto.SignerOpts) ([]byte, error) {
	return s.Signature, nil
}

// MockConn mocks a network connection, storing the read and write bytes
// internally to allow inspection. It implements io.ReadWriter.
type MockConn struct {
	ReadBuf  bytes.Buffer
	WriteBuf bytes.Buffer
}

func (c *MockConn) Read(p []byte) (int, error) {
	return c.ReadBuf.Read(p)
}

func (c *MockConn) Write(p []byte) (int, error) {
	return c.WriteBuf.Write(p)
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
				"D 2.4.7\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"D (7:sig-val(5:ecdsa(1:r32#2EEBA51CC802EDF6ACF44CB6B2506BFEDA8727CF9F623939420BCCD02F2C1B89#)(1:s32#8A3D09E0A2FED86802D6C6E2A429FF97F98B5FC9880442745C6D2F4557104070#)))\n",
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
			keyService := mock.NewMockKeyService(ctrl)
			keyService.EXPECT().HaveKey(gomock.Any()).AnyTimes().Return(true, nil, nil)
			keyService.EXPECT().GetSigner(gomock.Any()).Return(&MockCryptoSigner{
				PubKey:    pubKey,
				Signature: signature,
			}, nil)
			mockConn := MockConn{}
			log, err := zap.NewDevelopment()
			if err != nil {
				tt.Fatal(err)
			}
			n := notify.New(log, 6*time.Second)
			a := assuan.New(&mockConn, log, n, keyService)
			// write all the lines into the statemachine
			for _, in := range tc.input {
				if _, err := mockConn.ReadBuf.WriteString(in); err != nil {
					tt.Fatal(err)
				}
			}
			// start the state machine
			if err := a.Run(context.Background()); err != nil {
				tt.Fatal(err)
			}
			// check the responses
			for _, expected := range tc.expect {
				line, err := mockConn.WriteBuf.ReadString(byte('\n'))
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
		keyGrip string
		input   []string
		expect  []string
	}{
		"keyinfo": {
			keyPath: "testdata/C54A8868468BC138.asc",
			keyGrip: "38F053358EFD6C923D08EE4FC4CEB208CBCDF73C",
			input: []string{
				"RESET\n",
				"KEYINFO 38F053358EFD6C923D08EE4FC4CEB208CBCDF73C\n",
			},
			expect: []string{
				"OK Pleased to meet you, process 123456789\n",
				"OK\n",
				"S KEYINFO 38F053358EFD6C923D08EE4FC4CEB208CBCDF73C D - - - - - - -\n",
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
			keygrip, err := hex.DecodeString(tc.keyGrip)
			if err != nil {
				tt.Fatal(err)
			}
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			var mockSecurityKey = mock.NewMockSecurityKey(ctrl)
			mockSecurityKey.EXPECT().SigningKeys().AnyTimes().Return(
				[]securitykey.SigningKey{
					{CryptoKey: securitykey.CryptoKey{Public: pubKey}},
				})
			keyService := mock.NewMockKeyService(ctrl)
			keyService.EXPECT().HaveKey(gomock.Any()).AnyTimes().Return(
				true, keygrip, nil)
			// mockConn is a pair of buffers that the assuan statemachine reads/write
			// to/from.
			mockConn := MockConn{}
			log, err := zap.NewDevelopment()
			if err != nil {
				tt.Fatal(err)
			}
			n := notify.New(log, 6*time.Second)
			a := assuan.New(&mockConn, log, n, keyService)
			// write all the lines into the statemachine
			for _, in := range tc.input {
				if _, err := mockConn.ReadBuf.WriteString(in); err != nil {
					tt.Fatal(err)
				}
			}
			// start the state machine
			if err := a.Run(context.Background()); err != nil {
				tt.Fatal(err)
			}
			// check the responses
			for _, expected := range tc.expect {
				line, err := mockConn.WriteBuf.ReadString(byte('\n'))
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

func TestDecryptRSAKeyfile(t *testing.T) {
	var testCases = map[string]struct {
		keyPath string
		input   []string
		expect  []string
	}{
		// test data is taken from a successful decrypt by gpg-agent
		"decrypt file": {
			keyPath: "testdata/private/foo@example.com.gpg",
			input: []string{
				"RESET\n",
				"OPTION ttyname=/dev/pts/1\n",
				"OPTION ttytype=screen\n",
				"OPTION lc-ctype=C.UTF-8\n",
				"OPTION lc-messages=C\n",
				"GETINFO version\n",
				"OPTION allow-pinentry-notify\n",
				"OPTION agent-awareness=2.1.0\n",
				"HAVEKEY FC0F9A401ADDB33C0F7225CCA83BFC14E7FEBC7D\n",
				"HAVEKEY FC0F9A401ADDB33C0F7225CCA83BFC14E7FEBC7D\n",
				"HAVEKEY FC0F9A401ADDB33C0F7225CCA83BFC14E7FEBC7D\n",
				"RESET\n",
				"SETKEY FC0F9A401ADDB33C0F7225CCA83BFC14E7FEBC7D\n",
				"SETKEYDESC Please+enter+the+passphrase+to+unlock+the+OpenPGP+secret+key:%0A%22foo@example.com%22%0A3072-bit+RSA+key,+ID+8D0381C18D1E7CA6,%0Acreated+2021-08-04.%0A\n",
				"PKDECRYPT\n",
				"\x44\x20\x28\x37\x3a\x65\x6e\x63\x2d\x76\x61\x6c\x28\x33\x3a\x72\x73\x61\x28\x31\x3a\x61\x33\x38\x34\x3a\x59\xd1\x22\xac\x32\xf2\x15\xc7\xc6\xd8\x9c\xfa\xec\xf7\xd4\x71\x4f\x6f\xa7\x65\xf7\x7c\x38\x16\xff\x91\x7e\x7f\xb5\xc7\x6b\xb6\xf4\xcc\x24\x8b\xd8\x8e\x44\x25\x30\x44\xab\xf7\x79\x12\x8f\xe3\x06\x89\x7c\x2a\x31\xc3\x25\x30\x44\x46\xdf\xb5\x67\xde\x20\xc8\xce\xad\x72\x14\x5a\x2e\x0e\xfd\x25\x32\x35\x42\x25\x30\x41\x5d\x41\x3c\xb4\x75\xb3\xf0\x58\xd2\xd5\xe7\x2d\x1f\x12\xbc\x29\x59\x4a\xe1\x16\x16\xdf\x5a\x9a\x63\x48\xec\x00\x2f\x68\xa6\x82\x32\x70\x36\xbc\x4c\xf1\x0b\x69\x60\x06\xbd\x04\x37\xc1\x2c\x34\x8f\x13\xd8\x23\xbf\x86\x8c\xcd\x6c\xfa\xb1\xfa\x59\x28\x46\xcd\x55\x27\xa9\x80\x67\xd2\x7d\x63\xf5\xe6\x15\x14\x00\x97\x36\x70\x37\xde\xd9\x49\xa6\xbd\x4d\x44\x48\x69\x28\x25\x32\x35\xf4\x06\xeb\xbf\x89\x39\xbb\xb9\x0f\x8e\x92\x5a\x57\x15\xdc\x85\x87\x39\xae\x3d\xeb\x5c\x02\x7c\x08\xcc\x31\x0e\x55\x4d\x3e\xda\xb4\xba\x42\xce\x9a\xa5\x8d\xec\x4b\x45\x8c\x3a\xa2\x92\x70\xbe\x30\x48\x86\xae\x52\x2f\x83\x00\xba\x99\xcf\xdd\x8d\x69\x23\x8b\x25\x30\x41\x3b\x39\x7b\xa0\xc4\x81\x65\x32\xed\xa9\x37\x23\x12\xcb\x8d\xe9\xeb\xa6\x6e\x05\x03\x3f\x5f\x9d\x72\x29\xe0\x27\x17\x2a\x23\x34\xad\x83\xb2\xbc\x5e\x0e\x8e\x0e\xe5\xfb\xbd\xd6\x25\x30\x41\x63\x7e\x9a\x12\x15\x14\x8b\x98\x56\x0c\x2e\x50\xe3\xbb\xb4\x19\x7b\x1b\x6a\xd8\xdc\xa8\xbe\x8b\x38\xa8\x09\x07\xeb\x00\x60\x66\xf0\xd1\xb8\xe2\x37\x7e\x7f\xa4\x78\x62\xcb\xb6\xcb\x8c\xad\x73\x90\xcd\x4b\xb7\xb4\xf2\xb1\x80\x38\x23\x6f\x11\x11\xe4\x83\x6d\x93\x4f\x22\x26\xff\x60\xda\xdb\x85\x1b\x25\x30\x44\xa4\x3c\x26\xd9\x09\x86\xd9\xa3\x5f\x7c\xb4\xb5\xf5\x6a\x3d\xbe\x96\x25\x30\x41\x49\xbc\x92\x84\x02\xac\x0c\x30\x17\x9f\xb2\xd2\x11\x93\xfa\x1d\x37\x9c\x29\x29\x29\x0a",
				"END\n",
			},
			expect: []string{
				"OK Pleased to meet you, process 123456789\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"D 2.4.7\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"S INQUIRE_MAXLEN 4096\n",
				"INQUIRE CIPHERTEXT\n",
				"\x44\x20\x28\x35\x3a\x76\x61\x6c\x75\x65\x33\x38\x33\x3a\x02\xfd\x56\x90\x50\xc0\x73\xcf\x96\x6a\x12\xfb\xc7\x25\x30\x44\xa2\xc6\x0f\x4c\x3b\xd4\x0f\x2a\x89\xff\x66\x3f\x28\xe6\xd1\x39\x17\x78\x87\x25\x32\x35\x32\x0c\x9d\x2d\x73\xe3\xab\x79\xe5\x03\xc3\x78\x88\x5e\x11\x98\x4b\x44\x42\xd1\xfc\x75\xe4\xfb\xbf\x2f\x9f\x79\x3a\xf1\xe7\xa6\xe3\x23\xea\xcf\xed\x1f\x29\x77\x67\x50\x42\xba\xe9\x98\x78\x30\x07\x44\x73\x9c\x15\x16\xd3\x7a\x9a\xe3\xe9\x36\xf2\x8a\x29\xf4\x3d\xb0\xa5\x18\xf2\x45\xf2\x33\xd4\x25\x30\x41\xb2\xe5\x18\x1b\xad\x55\xec\x8d\x16\x66\xce\xf9\xe5\x3d\xcd\x21\x6e\x57\xd0\x61\xf1\xb5\xc9\x16\x40\x06\x59\x64\xaa\x15\xcf\x01\xf7\xd2\x4c\x21\x3e\xd7\xe4\xeb\xbe\xf1\x8f\xb9\x50\xef\x14\x39\xb6\x9c\x12\xac\x8a\x1e\x1c\xe6\x0e\x45\xa8\x81\x4f\xbf\xc4\x9d\xb4\xb1\x50\x28\xbb\x14\x7b\xb3\xbb\xd9\x37\x38\xb3\x11\x43\xbc\xab\x32\xf2\x74\x67\xf3\x36\xb8\x11\x5f\x97\x7e\x91\x42\x6c\xee\x23\xe4\x81\x8b\xf8\x5a\xd7\x18\x27\x03\x6f\xa6\xff\xa2\x4b\x54\x18\x20\x74\x12\x21\x5c\x7a\x5e\x26\x25\x30\x41\xc6\xd3\x58\x94\x45\x3b\x90\x63\x7f\xf7\x9a\xb3\x30\x9d\x0e\xfe\xa7\xa9\xb5\xff\x92\x38\x15\x8b\x13\x46\x48\xd8\x9e\xca\xc4\xc2\xae\x65\x4d\xbb\xc1\xe5\x36\xf0\x56\x27\x96\x2b\x45\x4d\xc4\xed\xe5\x6f\x0e\x2b\x2f\x52\x47\x7f\x60\x09\x27\x0b\x30\xcb\x14\x65\x4e\xd2\xff\x9b\xdf\xd9\xb9\x0b\x7e\x07\x29\xba\x78\x47\x8e\x9d\x4a\x37\x0c\xee\x02\xb3\x65\xd7\x15\xba\xbb\xeb\x4b\xbd\xed\xd0\xcf\xae\x90\x31\x8a\x2d\x47\xfa\xc6\x1a\xac\xee\xf5\x82\x77\x28\x46\xce\x8a\x50\xc6\x00\x09\x9e\xf9\xb9\x35\x26\xbb\x2d\xcb\x9b\x60\x8d\x2e\xd3\x04\x95\xc7\xf5\x64\x97\xe6\x90\xf4\x7a\xb0\x50\xf4\x96\x99\x67\x36\xe6\x2f\x11\xf0\x29\x00\x0a",
				"OK\n",
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			// no securityKeys available
			mockPES := mock.NewMockPINEntryService(ctrl)
			log, err := zap.NewDevelopment()
			if err != nil {
				tt.Fatal(err)
			}
			// mockConn is a pair of buffers that the assuan statemachine reads/write
			// to/from.
			mockConn := MockConn{}
			n := notify.New(log, 6*time.Second)
			a := assuan.New(&mockConn, log, n, gpg.New(log, mockPES, tc.keyPath))
			// write all the lines into the statemachine
			for _, in := range tc.input {
				if _, err := mockConn.ReadBuf.WriteString(in); err != nil {
					tt.Fatal(err)
				}
			}
			// start the state machine
			if err := a.Run(context.Background()); err != nil {
				tt.Fatal(err)
			}
			// check the responses
			for _, expected := range tc.expect {
				// spew.Dump(mockConn.WriteBuf.String())
				line, err := mockConn.WriteBuf.ReadString(byte('\n'))
				if err != nil && err != io.EOF {
					tt.Fatal(err)
				}
				if line != expected {
					fmt.Println("got")
					spew.Dump(line)
					fmt.Println("expected")
					spew.Dump(expected)
					tt.Fatalf("error")
				}
			}
		})
	}
}

func TestSignRSAKeyfile(t *testing.T) {
	var testCases = map[string]struct {
		keyPath string
		input   []string
		expect  []string
	}{
		// test data is taken from a successful decrypt by gpg-agent
		"decrypt file": {
			keyPath: "testdata/private/foo@example.com.gpg",
			input: []string{
				"RESET\n",
				"OPTION ttyname=/dev/pts/1\n",
				"OPTION ttytype=screen\n",
				"OPTION lc-ctype=C.UTF-8\n",
				"OPTION lc-messages=C\n",
				"GETINFO version\n",
				"OPTION allow-pinentry-notify\n",
				"OPTION agent-awareness=2.1.0\n",
				"SCD SERIALNO\n",
				"HAVEKEY FC0F9A401ADDB33C0F7225CCA83BFC14E7FEBC7D\n",
				"KEYINFO FC0F9A401ADDB33C0F7225CCA83BFC14E7FEBC7D\n",
				"RESET\n",
				"SIGKEY FC0F9A401ADDB33C0F7225CCA83BFC14E7FEBC7D\n",
				"SETKEYDESC Please+enter+the+passphrase+to+unlock+the+OpenPGP+secret+key:%0A%22foo@example.com%22%0A3072-bit+RSA+key,+ID+8D0381C18D1E7CA6,%0Acreated+2021-08-04.%0A\n",
				"SETHASH 8 5963E1FA635CA32A85CA43CDCE3CB7A0CB0429B0EB1A94D1AEF08801D3BEB465\n",
				"PKSIGN\n",
			},
			expect: []string{
				"OK Pleased to meet you, process 123456789\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"D 2.4.7\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"ERR 100696144 No such device <SCD>\n",
				"OK\n",
				"S KEYINFO FC0F9A401ADDB33C0F7225CCA83BFC14E7FEBC7D D - - - - - - -\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"\x44\x20\x28\x37\x3a\x73\x69\x67\x2d\x76\x61\x6c\x28\x33\x3a\x72\x73\x61\x28\x31\x3a\x73\x33\x38\x34\x3a\xb3\x26\x74\x5f\x59\xb5\x50\x8a\x46\x37\xa0\xc0\x91\x3a\x4b\x18\x61\xcb\x4f\xd2\x52\x5d\xbc\xe5\x51\x41\x00\x25\x30\x44\x08\x20\x25\x30\x41\xac\x0b\xff\x3e\xed\x6a\xa4\xf0\xdc\xb9\x1f\x8f\x76\xf1\x30\x8f\xce\xdc\xf5\x79\x2d\x2f\x06\x52\x3b\x49\xd5\x7d\xa1\x4a\xa2\x38\x81\x56\x6c\x59\xb0\x56\x22\xd8\x13\xeb\x7a\xee\xb1\xc5\xd6\xe9\xa0\x3a\xf4\x1b\x12\xa0\x85\x74\xe9\x93\x80\x7d\x7f\x24\xc8\x59\x9d\xb2\x8a\xe6\xc3\x95\xee\x50\x4c\x12\x4a\x1d\x84\x46\x3f\xa2\xc8\x96\xc2\xdf\xb7\x3d\x54\xa0\x55\x4a\x46\x4b\x35\x9f\xf0\x32\x9a\xd9\x0e\xe8\xa3\xa9\xb1\x3b\xa6\x52\x63\x02\xce\x36\x8f\x94\x18\x39\x3e\x11\x26\xb0\xa9\x71\xb8\x1c\x35\x47\xe8\x78\x8d\x12\xcf\x42\x96\xc7\x37\x25\x30\x41\x16\xa4\xbb\x83\x42\xe0\xa7\xed\x11\x35\x84\x5b\x40\xcd\x52\xc5\xd2\xf4\xe2\x86\x8b\x23\x42\x54\xda\xd1\xcd\xfc\x3e\xb2\x84\x1e\x2b\x04\xfb\x72\x04\x2f\xa9\x80\xf7\xa3\x13\x9a\xee\xe0\x26\x17\x6f\xdb\x57\x91\x85\xce\xbc\x5a\x97\x62\x8b\xa4\xa2\x54\x1c\x03\xc0\x3a\x9b\x8e\x4b\x32\x5e\x39\x71\x25\x30\x44\x8e\xae\x14\x09\x05\xcb\x77\x8d\x61\x2a\x4b\x1f\x19\x21\x8a\x68\x80\xd0\x4e\x53\x30\xc3\xab\x03\xd3\x79\x77\x55\xff\x2e\x46\xe3\x08\x03\x86\xef\xe1\xed\x34\x20\x08\x7a\xee\x1f\x0e\xd6\xf0\xbe\xe7\xdd\xab\xf6\x46\xec\xce\xd5\xa6\xc4\xf4\x02\x58\x5a\xcb\x6d\x9f\x2e\xf7\x24\x71\x9e\x13\x24\x22\x42\xe4\x48\xd5\x25\x32\x35\x1f\xac\xfc\x2c\xe2\x5c\x7c\xdb\xaf\xd2\x45\x3c\x99\xe1\xba\xd3\xd4\x95\x9d\xf8\xa1\x21\xca\x3f\xf9\x7b\x08\x50\x75\x13\x7a\x3d\xc9\x48\x9d\x4a\x93\xb6\xb5\x7a\x15\xef\xa6\x4d\xa9\x87\x41\x0e\xde\x25\x32\x35\x04\x18\x41\xa9\x4d\x9c\xbf\x12\x1f\x48\xc0\xa8\x92\xfd\x37\x7d\xec\x29\x29\x29\x0a",
				"OK\n",
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			// no securityKeys available
			mockPES := mock.NewMockPINEntryService(ctrl)
			log, err := zap.NewDevelopment()
			if err != nil {
				tt.Fatal(err)
			}
			// mockConn is a pair of buffers that the assuan statemachine reads/write
			// to/from.
			mockConn := MockConn{}
			n := notify.New(log, 6*time.Second)
			a := assuan.New(&mockConn, log, n, gpg.New(log, mockPES, tc.keyPath))
			// write all the lines into the statemachine
			for _, in := range tc.input {
				if _, err := mockConn.ReadBuf.WriteString(in); err != nil {
					tt.Fatal(err)
				}
			}
			// start the state machine
			if err := a.Run(context.Background()); err != nil {
				tt.Fatal(err)
			}
			// check the responses
			for _, expected := range tc.expect {
				// spew.Dump(mockConn.WriteBuf.String())
				line, err := mockConn.WriteBuf.ReadString(byte('\n'))
				if err != nil && err != io.EOF {
					tt.Fatal(err)
				}
				if line != expected {
					fmt.Println("got")
					spew.Dump(line)
					fmt.Println("expected")
					spew.Dump(expected)
					tt.Fatalf("error")
				}
			}
		})
	}
}

func TestReadKey(t *testing.T) {
	var testCases = map[string]struct {
		keyPath string
		input   []string
		expect  []string
	}{
		"rsa": {
			keyPath: "testdata/private-subkeys",
			input: []string{
				"RESET\n",
				"READKEY EA8E47C68880D1620FF10CC7CB91E5605758CC8D\n",
				"SETKEYDESC Please+enter+the+passphrase+to+unlock+the+OpenPGP+secret+key:%0A%22foo@example.com%22%0A3072-bit+RSA+key,+ID+AD024955495A860B,%0Acreated+2021-08-07.%0A\n",
				"PASSWD  --verify B242AADA8260B77F0F5069F127D6B7E4F44B5FAA\n",
			},
			expect: []string{
				"OK Pleased to meet you, process 123456789\n",
				"OK\n",
				"\x44\x20\x28\x31\x30\x3a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x28\x33\x3a\x72\x73\x61\x28\x31\x3a\x6e\x33\x38\x35\x3a\x00\xbe\xe3\x07\x13\x3c\xae\xd7\x10\xe4\xdd\x84\x20\xc3\x96\xba\xdc\xe0\x09\x6d\xce\xbf\xc2\x55\xe3\x24\x4b\x96\x76\xf5\xd9\xcf\x02\x58\xbf\x69\x16\xcf\x2a\xa4\xdc\x8c\x82\x57\xb0\x5a\x16\x74\xf6\xd5\x21\xee\xdc\xce\x89\x64\xcd\x66\xf5\xee\x89\x09\xa6\x44\xce\x9d\x03\xc0\x44\x4d\x90\xdf\x60\x07\xc6\xf8\x2f\x98\x07\x9b\x95\xb3\xe5\x16\xb8\x1d\x59\xd1\x19\x97\x4c\x36\xbd\xce\xc7\xe1\x17\x7d\x6a\xdc\xa0\x16\x93\x2c\x91\x70\x7c\xf2\x1b\xd9\x5b\x4a\xd5\x46\x65\x9e\x09\xcc\x38\xbe\x86\xbd\xdd\xbf\x91\x7c\x04\x6c\xba\x38\xaf\xe6\xb4\xbb\x38\xa0\x3b\x3b\x07\x60\x2e\xbb\x6d\x45\x31\x1b\x0e\x37\x85\xdb\xa0\x93\xa5\x5c\xf6\xde\x69\x9e\x66\x3e\xa2\x3c\xf9\x59\x4b\x18\xc5\x5b\xdb\x4d\xa8\xcb\x80\xe6\xf9\x52\x1e\x2c\xb8\xab\xac\x7b\x14\xe9\xa8\x6a\x6d\xc6\x51\xb1\x74\x02\xa5\x13\x58\x66\x25\x32\x35\x3b\xed\xe3\x63\xb2\x7a\x8f\x93\x9b\x2c\x04\xdd\xf6\x56\xa9\xb2\x40\x34\xa9\x9b\xe6\xe1\x33\x5b\xe2\xa8\x12\x18\x48\x4e\xa6\xb7\xdd\xbf\xf0\xd2\x70\x18\x7b\x9d\xd3\xec\x55\x5f\xb7\xe8\x07\x1a\x90\x1e\xe4\x68\xa9\x67\x5c\xda\xe9\xea\x29\x19\xeb\x4c\x1c\x6a\x44\x06\x39\xea\xa2\xda\x29\x49\xdf\xd1\x00\x86\x5a\xe2\xe2\xe0\xa4\xa6\x2f\x74\x57\xbc\x78\x75\xa9\xd6\x81\xb1\x11\xbd\xca\x08\x17\x56\x9f\x42\xfe\x3f\x1a\xd1\x7e\xb2\x90\x27\x8a\x31\x8c\x88\x32\x3a\x28\x90\x10\xaf\x4d\xf8\x51\x94\x6f\x29\x21\xa4\x74\xfb\x65\x24\xcc\x5f\x48\x68\xdd\xff\x41\xb2\xe4\xa7\xbf\x25\x32\x35\xbe\x8d\xd8\x9f\x95\xd3\x7d\xe8\xf2\x4b\x78\xa1\x93\x29\xa5\x8b\xfa\x8d\x83\x6e\xbf\x9c\x5b\x1e\x38\xe3\x47\x60\xc6\xde\x4a\xd0\x78\x80\x6f\x20\xbf\xfd\x63\x12\x6f\xdd\xa3\x81\xf5\xf9\x29\x28\x31\x3a\x65\x33\x3a\x01\x00\x01\x29\x29\x29\x0a",
				"OK\n",
				"OK\n",
			},
		},
		"ecdsa": {
			keyPath: "testdata/private-subkeys",
			input: []string{
				"RESET\n",
				"READKEY 586A6F8E9CD839FD26D868D084DDFEBB0CCC7EF0\n",
				"SETKEYDESC Please+enter+the+passphrase+to+unlock+the+OpenPGP+secret+key:%0A%22foo@example.com%22%0A3072-bit+RSA+key,+ID+AD024955495A860B,%0Acreated+2021-08-07.%0A\n",
				"PASSWD  --verify B242AADA8260B77F0F5069F127D6B7E4F44B5FAA\n",
			},
			expect: []string{
				"OK Pleased to meet you, process 123456789\n",
				"OK\n",
				"\x44\x20\x28\x31\x30\x3a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x28\x33\x3a\x65\x63\x63\x28\x35\x3a\x63\x75\x72\x76\x65\x31\x30\x3a\x4e\x49\x53\x54\x20\x50\x2d\x32\x35\x36\x29\x28\x31\x3a\x71\x36\x35\x3a\x04\xbf\x06\xac\x95\x31\xae\x04\x93\x98\x21\x03\x83\x35\x9d\x4e\x58\x92\xa2\xe9\x24\x2f\x76\x54\x67\x45\xf0\x35\x28\xf4\x47\x14\x59\x26\x0c\xf9\x1b\x24\x10\x6b\x07\xe3\x33\x05\x4c\xcb\x96\xe2\xdd\x96\xd4\x0f\x3e\x4b\xd7\x67\x44\xdb\x82\x42\x24\xe6\x8b\x7f\xa6\x29\x29\x29\x0a",
				"OK\n",
				"OK\n",
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			// no securityKeys available
			mockPES := mock.NewMockPINEntryService(ctrl)
			log, err := zap.NewDevelopment()
			if err != nil {
				tt.Fatal(err)
			}
			// mockConn is a pair of buffers that the assuan statemachine reads/write
			// to/from.
			mockConn := MockConn{}
			n := notify.New(log, 6*time.Second)
			a := assuan.New(&mockConn, log, n, gpg.New(log, mockPES, tc.keyPath))
			// write all the lines into the statemachine
			for _, in := range tc.input {
				if _, err := mockConn.ReadBuf.WriteString(in); err != nil {
					tt.Fatal(err)
				}
			}
			// start the state machine
			if err := a.Run(context.Background()); err != nil {
				tt.Fatal(err)
			}
			// check the responses
			for _, expected := range tc.expect {
				line, err := mockConn.WriteBuf.ReadString(byte('\n'))
				if line != expected {
					tt.Log("got", spew.Sdump(line))
					tt.Log("expected", spew.Sdump(expected))
					tt.Fail()
				}
				if err != nil && err != io.EOF {
					tt.Fatal(err)
				}
			}
		})
	}
}

func TestDecryptECDHKeyfile(t *testing.T) {
	var testCases = map[string]struct {
		keyPath string
		input   []string
		expect  []string
	}{
		// test data is taken from a successful decrypt by gpg-agent
		"decrypt file": {
			keyPath: "testdata/private/test-assuan2@example.com.gpg",
			input: []string{
				"RESET\n",
				"OPTION ttyname=/dev/pts/12\n",
				"OPTION ttytype=xterm-256color\n",
				"OPTION display=:0\n",
				"OPTION xauthority=/run/user/1000/.mutter-Xwaylandauth.PAZSA1\n",
				"OPTION putenv=XMODIFIERS=@im=ibus\n",
				"OPTION putenv=WAYLAND_DISPLAY=wayland-0\n",
				"OPTION putenv=XDG_SESSION_TYPE=wayland\n",
				"OPTION putenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus\n",
				"OPTION putenv=QT_IM_MODULE=ibus\n",
				"OPTION lc-ctype=en_AU.UTF-8\n",
				"OPTION lc-messages=en_AU.UTF-8\n",
				"GETINFO version\n",
				"OPTION allow-pinentry-notify\n",
				"OPTION agent-awareness=2.1.0\n",
				"SCD SERIALNO\n",
				"SCD SERIALNO\n",
				"SCD KEYINFO --list=encr\n",
				"HAVEKEY --list=1000\n",
				"RESET\n",
				"SETKEY 98E3311ADC66E078D1A4BEBEBBC498D1E5765A8D\n",
				"SETKEYDESC Please+enter+the+passphrase+to+unlock+the+OpenPGP+secret+key:%0A%22test-assuan@example.com%22%0A256-bit+ECDH+key,+ID+0x419969CE7D167442,%0Acreated+2021-10-10+(main+key+ID+0xFDB0A7FF92431C37).%0A\n",
				"PKDECRYPT\n",
				"\x44\x20\x28\x37\x3a\x65\x6e\x63\x2d\x76\x61\x6c\x28\x34\x3a\x65\x63\x64\x68\x28\x31\x3a\x73\x34\x39\x3a\x30\xc0\xc4\x09\xb5\x8a\x36\xb8\x09\xa6\xcc\xaf\x9c\x46\x65\x92\xaa\xef\xe8\xae\x67\xb5\x28\x65\xfa\x8a\x8f\x11\x38\xed\xcc\xa5\xe6\x7a\xcf\xcb\x82\xc3\x51\xe9\xa8\x8d\xbd\xb1\x43\x49\x50\x8e\x82\x29\x28\x31\x3a\x65\x36\x35\x3a\x04\xcb\x0c\x10\x45\xaf\x3b\xfa\x3e\x44\x3c\x35\xe0\xf8\xa8\x11\xa9\xd0\x3f\x50\xc0\x93\xea\x71\x99\x81\x39\x51\xa1\x2e\x7f\xd8\x90\xd4\x1d\x89\x9f\x62\x1d\x08\xfa\x15\x81\x45\x10\x42\x92\x17\xd7\x97\xf0\x8d\x86\x9a\x74\x3d\x8a\x5e\xfb\xa3\xc3\x98\x06\xbd\x50\x29\x29\x29\x0a",
				"END\n",
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
				"OK\n",
				"D 2.4.7\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"ERR 100696144 No such device <SCD>\n",
				"ERR 100696144 No such device <SCD>\n",
				"ERR 100696144 No such device <SCD>\n",
				"\x44\x20\x98\xe3\x31\x1a\xdc\x66\xe0\x78\xd1\xa4\xbe\xbe\xbb\xc4\x98\xd1\xe5\x76\x5a\x8d\x0a",
				"OK\n",
				"OK\n",
				"OK\n",
				"OK\n",
				"S INQUIRE_MAXLEN 4096\n",
				"INQUIRE CIPHERTEXT\n",
				"\x44\x20\x28\x35\x3a\x76\x61\x6c\x75\x65\x36\x35\x3a\x04\xc8\x50\x0c\x67\x98\x95\x86\x1b\x6c\xa4\x4f\x9f\x8d\x17\xf2\xf8\x71\xbc\xe5\xa3\xe5\xe6\xc4\xae\x01\xfa\x04\x6c\xc9\xc4\x2c\x9a\x56\x52\x2b\xab\x62\xa6\x29\xdb\x12\xc0\xc2\x62\xa0\x36\xd0\x93\x46\x99\xe5\x35\xca\xc4\xbe\xe6\x05\xa5\xae\x7f\xb2\x3c\xbb\x2f\x29\x0a",
				"OK\n",
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			// no securityKeys available
			mockPES := mock.NewMockPINEntryService(ctrl)
			log, err := zap.NewDevelopment()
			if err != nil {
				tt.Fatal(err)
			}
			// mockConn is a pair of buffers that the assuan statemachine reads/write
			// to/from.
			mockConn := MockConn{}
			n := notify.New(log, 6*time.Second)
			a := assuan.New(&mockConn, log, n, gpg.New(log, mockPES, tc.keyPath))
			// write all the lines into the statemachine
			for _, in := range tc.input {
				if _, err := mockConn.ReadBuf.WriteString(in); err != nil {
					tt.Fatal(err)
				}
			}
			// start the state machine
			if err := a.Run(context.Background()); err != nil {
				tt.Fatal(err)
			}
			// check the responses
			for _, expected := range tc.expect {
				line, err := mockConn.WriteBuf.ReadString(byte('\n'))
				if err != nil && err != io.EOF {
					tt.Fatal(err)
				}
				if line != expected {
					fmt.Println("got")
					spew.Dump(line)
					fmt.Println("expected")
					spew.Dump(expected)
					tt.Fatalf("error")
				}
			}
		})
	}
}
