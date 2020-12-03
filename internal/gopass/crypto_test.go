package gopass_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/smlx/piv-agent/internal/gopass"
	"github.com/smlx/piv-agent/internal/gopass/pb"
	"github.com/smlx/piv-agent/internal/mock"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

//go:generate mockgen -source=gopass.go -destination ../mock/mock_gopass.go -package mock

func TestEncrypt(t *testing.T) {
	var testCases = map[string]struct {
		plaintext  []byte
		recipients [][]byte
	}{
		"ecdsa encrypt": {
			plaintext: []byte("ACollectionOfDiplomaticHistorySince_1966_ToThe_PresentDay#"),
			recipients: [][]byte{
				[]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGRI872xXZQBh1xScAcLZ2Lk41tUylsWhCDcEcpCtGGVC1TdtrPZ8uciYE5P5xBuwI8kT+PbR33op87pjKsye5M= scott@thinky"),
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			mockCtrl := gomock.NewController(tt)
			defer mockCtrl.Finish()

			exitTicker := time.NewTicker(time.Hour)
			defer exitTicker.Stop()

			log, err := zap.NewDevelopment()
			if err != nil {
				tt.Fatal(err)
			}
			defer log.Sync()

			mockAgent := mock.NewMockAgent(mockCtrl)

			// mockAgent is not actually used in Decrypt()

			crypto := gopass.NewCrypto(mockAgent, exitTicker, log, name)

			ciphertext, err := crypto.Encrypt(context.TODO(), &pb.EncryptArgs{
				Plaintext:  tc.plaintext,
				Recipients: tc.recipients,
			})
			if err != nil {
				tt.Fatal(err)
			} else {
				tt.Log(string(ciphertext.Ciphertext))
				tt.Log(base64.StdEncoding.EncodeToString(ciphertext.Ciphertext))
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	var testCases = map[string]struct {
		ciphertext       string
		recipientPrivKey string
		recipientPubKey  []byte
	}{
		"ecdsa decrypt": {
			ciphertext: "LSBDaXBoZXJ0ZXh0OiBZTmtwWFcwQUdUMjIzL3JTREQ5eHZQK2pLSzlFM3QzQTRVMVlQU2tEWWFieTR3Ukd4K2RHSlc1NTIxbnZlN2IrSnlIdWtWWHdhc3RnUTNOcTlSY2w1c2wwRjl0aGhvajFEcVk9CiAgS2V5VHlwZTogZWNkc2Etc2hhMi1uaXN0cDI1NgogIE5vbmNlOiBSTWdEaS9LZ1dxWCtmUVV1cmRJbFpSV3JjVGsrRzE5cwogIFB1YktleTogZ3FGWXhFd3lNelF5T1Rnek5qazFPVEE1TlRVME5UWXhPVFU0TlRJME5EazVOVFF6TmpJeU5qZzBNelEyTXpBNU56QTVPVFUwT0RnNE5EWTFOREExTVRFMU5USXpNRFE0T1RRNE5EQTBNREk1b1ZuRVRUSTVOelUzTkRrd01qTTJNVEUxTWpJNE16TTNNRFkzTXpnek1UVTBOVGd6TlRnMU5ETXhNVFUxTlRNNE5EYzVPVFEzTmpVek5qVXlPREV6TnpBME5UUTJNREV4Tnpnd05EQTVNakF4CiAgUmVjaXBpZW50OiBaV05rYzJFdGMyaGhNaTF1YVhOMGNESTFOaUJCUVVGQlJUSldhbHBJVG1oTVdFNXZXVlJKZEdKdGJIcGtTRUY1VGxSWlFVRkJRVWxpYld4NlpFaEJlVTVVV1VGQlFVSkNRa2RTU1RnM01uaFlXbEZDYURGNFUyTkJZMHhhTWt4ck5ERjBWWGxzYzFkb1EwUmpSV053UTNSSFIxWkRNVlJrZEhKUVdqaDFZMmxaUlRWUU5YaENkWGRKT0d0VUsxQmlVak16YjNBNE4zQnFTM041WlRWTlBTQnpZMjkwZEVCMGFHbHVhM2s9CiAgU2FsdDogVzVGNTJqeGd6V2h5b0g4WVFoRCtxTFZ2akhFPQo=",
			recipientPrivKey: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRkSPO9sV2UAYdcUnAHC2di5ONbVMpb
FoQg3BHKQrRhlQtU3baz2fLnImBOT+cQbsCPJE/j20d96KfO6YyrMnuTAAAAqD04GEY9OB
hGAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGRI872xXZQBh1xS
cAcLZ2Lk41tUylsWhCDcEcpCtGGVC1TdtrPZ8uciYE5P5xBuwI8kT+PbR33op87pjKsye5
MAAAAgOjmf0Xj+TslpG/iDQA7M985bZdIN2JRmpqWmijsDb4EAAAAMc2NvdHRAdGhpbmt5
AQIDBA==
-----END OPENSSH PRIVATE KEY-----
`,
			recipientPubKey: []byte(`ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGRI872xXZQBh1xScAcLZ2Lk41tUylsWhCDcEcpCtGGVC1TdtrPZ8uciYE5P5xBuwI8kT+PbR33op87pjKsye5M= scott@thinky`),
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			mockCtrl := gomock.NewController(tt)
			defer mockCtrl.Finish()

			exitTicker := time.NewTicker(time.Hour)
			defer exitTicker.Stop()

			log, err := zap.NewDevelopment()
			if err != nil {
				tt.Fatal(err)
			}
			defer log.Sync()

			mockAgent := mock.NewMockAgent(mockCtrl)

			pubKey, _, _, _, err := ssh.ParseAuthorizedKey(tc.recipientPubKey)
			if err != nil {
				tt.Fatal(err)
			}
			tt.Log(base64.StdEncoding.EncodeToString(ssh.MarshalAuthorizedKey(pubKey)))
			mockAgent.EXPECT().PublicKeys().Return([]ssh.PublicKey{pubKey}, nil)

			crypto := gopass.NewCrypto(mockAgent, exitTicker, log, name)

			cipherBytes, err := base64.StdEncoding.DecodeString(tc.ciphertext)
			if err != nil {
				tt.Fatal(err)
			}
			tt.Log(string(cipherBytes))

			cleartext, err := crypto.Decrypt(context.TODO(), &pb.DecryptArgs{
				Ciphertext: cipherBytes,
			})
			if err != nil {
				tt.Fatal(err)
			} else {
				tt.Log(cleartext.Cleartext)
			}
		})
	}
}
