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

//go:generate mockgen -source=crypto.go -destination ../mock/mock_crypto.go -package mock

func TestEncrypt(t *testing.T) {
	var testCases = map[string]struct {
		plaintext  []byte
		recipients [][]byte
	}{
		"ecdsa encrypt": {
			plaintext: []byte("ACollectionOfDiplomaticHistorySince_1966_ToThe_PresentDay#"),
			recipients: [][]byte{
				[]byte(`ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKKswT9iBGEqD9tafHVCvYpRsdQk9lyUrb3eyDI6g2hwL4l3zOozpWtCnTqYQI1MONs/U+/xUlTHsl42Kt73dO4= scott@thinky`),
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
			ciphertext: `LSBDaXBoZXJ0ZXh0OiBGM1pmY3c1a2t2QmVNdzBBN21KMUFON1hreU1BRVJlZGI3WEtHaWZCMnlJaGgzSlVIbTBqazl0WDBwZmttbmVObDB5akRweExmb2NLV0tkTHBvdktwSmxzQktWb2tZRkM2RzQ9CiAgS2V5VHlwZTogZWNkc2Etc2hhMi1uaXN0cDI1NgogIE5vbmNlOiBtR3Q3bkZXWThtcExnTXlvK1JIUEdRcytNTlpGdDB6RAogIFB1YktleTogWldOa2MyRXRjMmhoTWkxdWFYTjBjREkxTmlCQlFVRkJSVEpXYWxwSVRtaE1XRTV2V1ZSSmRHSnRiSHBrU0VGNVRsUlpRVUZCUVVsaWJXeDZaRWhCZVU1VVdVRkJRVUpDUWtsU1dITmlUVmc1Y2xCT2RIUlBVMkpCWjJodksxQkdXVFpwV21KU2NuQlNlRXRXTjFaMU5VZHFUV2hKVDI5a1QzWlNVVFZyVldGbmIyMUdURnB0TkdKMGEwZEpTMHROTXpReGVXeEdiakJFU2trMlZYVnpQUW89CiAgUmVjaXBpZW50OiBaV05rYzJFdGMyaGhNaTF1YVhOMGNESTFOaUJCUVVGQlJUSldhbHBJVG1oTVdFNXZXVlJKZEdKdGJIcGtTRUY1VGxSWlFVRkJRVWxpYld4NlpFaEJlVTVVV1VGQlFVSkNRa3RMYzNkVU9XbENSMFZ4UkRsMFlXWklWa04yV1hCU2MyUlJhemxzZVZWeVlqTmxlVVJKTm1jeWFIZE1OR3d6ZWs5dmVuQlhkRU51VkhGWlVVa3hUVTlPY3k5Vkt5OTRWV3hVU0hOc05ESkxkRGN6WkU4MFBRbz0KICBTYWx0OiBpbHMzY0RrV3craDJ1eXZtOFpMNXdnTzBteFE9Cg==`,
			recipientPrivKey: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSirME/YgRhKg/bWnx1Qr2KUbHUJPZc
lK293sgyOoNocC+Jd8zqM6VrQp06mECNTDjbP1Pv8VJUx7JeNire93TuAAAAqAMd6qcDHe
qnAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKKswT9iBGEqD9ta
fHVCvYpRsdQk9lyUrb3eyDI6g2hwL4l3zOozpWtCnTqYQI1MONs/U+/xUlTHsl42Kt73dO
4AAAAhANbGYPozS3Clxxs0h64uzRWKU12d6Xm/ZNtLpa/wW2V1AAAADHNjb3R0QHRoaW5r
eQECAw==
-----END OPENSSH PRIVATE KEY-----`,
			recipientPubKey: []byte(`ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKKswT9iBGEqD9tafHVCvYpRsdQk9lyUrb3eyDI6g2hwL4l3zOozpWtCnTqYQI1MONs/U+/xUlTHsl42Kt73dO4= scott@thinky`),
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
			tt.Log("recipient pub key", base64.StdEncoding.EncodeToString(ssh.MarshalAuthorizedKey(pubKey)))
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
