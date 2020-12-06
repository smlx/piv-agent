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

func TestECDSAEncrypt(t *testing.T) {
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

			// mockAgent is not usually used in Encrypt(), since there is no need to
			// access the token.

			crypto := gopass.NewCrypto(mockAgent, exitTicker, log, name)

			ciphertext, err := crypto.Encrypt(context.TODO(), &pb.EncryptArgs{
				Plaintext:  tc.plaintext,
				Recipients: tc.recipients,
			})
			if err != nil {
				tt.Fatal(err)
			} else {
				tt.Log("secret entry:\n", string(ciphertext.Ciphertext))
				tt.Log("secret entry base64 encoded:\n", base64.StdEncoding.EncodeToString(ciphertext.Ciphertext))
			}
		})
	}
}

func TestECDSADecrypt(t *testing.T) {
	var testCases = map[string]struct {
		secretEntry         string
		recipientPrivateKey string
		recipientPublicKey  []byte
	}{
		"ecdsa decrypt": {
			secretEntry: `LSBDaXBoZXJ0ZXh0OiBkVUkvTkRaTXdzaDVyaEt6eWZuSlh1a1RFQ1cwaXFWaWFpalErK1dxOTJuSXlxOGhLTWIrS05pRDlwS1NJK3ZST1BvWkU3N0R6VlJXTFpvRGx6eXNFa3VFVEMzbE5GdS9VQVE9CiAgUHViS2V5OiBaV05rYzJFdGMyaGhNaTF1YVhOMGNESTFOaUJCUVVGQlJUSldhbHBJVG1oTVdFNXZXVlJKZEdKdGJIcGtTRUY1VGxSWlFVRkJRVWxpYld4NlpFaEJlVTVVV1VGQlFVSkNRa3g1SzJsU1VEUTJaRE16VldsRk9GTlhjR05vYjI5SWFGWlFPVEpSUjBvNVJVdFlTMUJXVTJSQlNVWjRWemxoVUVWb1VITjNOMlJWWlVjM01tY3hPWEJ2UTNKUGMyVTBlbWhLYTNZMFFYbFpPRFZrV0ROclBRbz0KICBSZWNpcGllbnQ6IFpXTmtjMkV0YzJoaE1pMXVhWE4wY0RJMU5pQkJRVUZCUlRKV2FscElUbWhNV0U1dldWUkpkR0p0Ykhwa1NFRjVUbFJaUVVGQlFVbGliV3g2WkVoQmVVNVVXVUZCUVVKQ1FrdExjM2RVT1dsQ1IwVnhSRGwwWVdaSVZrTjJXWEJTYzJSUmF6bHNlVlZ5WWpObGVVUkpObWN5YUhkTU5Hd3plazl2ZW5CWGRFTnVWSEZaVVVreFRVOU9jeTlWS3k5NFZXeFVTSE5zTkRKTGREY3paRTgwUFFvPQogIFNhbHQ6IC82d1dFbUxlSUlDcDUwSld1VzNXc3lhUk1wZz0K`,
			recipientPrivateKey: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSirME/YgRhKg/bWnx1Qr2KUbHUJPZc
lK293sgyOoNocC+Jd8zqM6VrQp06mECNTDjbP1Pv8VJUx7JeNire93TuAAAAqAMd6qcDHe
qnAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKKswT9iBGEqD9ta
fHVCvYpRsdQk9lyUrb3eyDI6g2hwL4l3zOozpWtCnTqYQI1MONs/U+/xUlTHsl42Kt73dO
4AAAAhANbGYPozS3Clxxs0h64uzRWKU12d6Xm/ZNtLpa/wW2V1AAAADHNjb3R0QHRoaW5r
eQECAw==
-----END OPENSSH PRIVATE KEY-----`,
			recipientPublicKey: []byte(`ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKKswT9iBGEqD9tafHVCvYpRsdQk9lyUrb3eyDI6g2hwL4l3zOozpWtCnTqYQI1MONs/U+/xUlTHsl42Kt73dO4= scott@thinky`),
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

			pubKey, _, _, _, err := ssh.ParseAuthorizedKey(tc.recipientPublicKey)
			if err != nil {
				tt.Fatal(err)
			}
			mockAgent.EXPECT().PublicKeys().Return([]ssh.PublicKey{pubKey}, nil)
			mockAgent.EXPECT().SharedKey(gomock.Any(), gomock.Any()).
				Return(base64.StdEncoding.DecodeString(
					`tQKCflnXc51A4Nc4anX23ojD/4oMGkEKMYqtSh4CmUg=`))

			crypto := gopass.NewCrypto(mockAgent, exitTicker, log, name)

			cipherBytes, err := base64.StdEncoding.DecodeString(tc.secretEntry)
			if err != nil {
				tt.Fatal(err)
			}
			tt.Log("decrypting secret entry\n", string(cipherBytes))

			cleartext, err := crypto.Decrypt(context.TODO(), &pb.DecryptArgs{
				Ciphertext: cipherBytes,
			})
			if err != nil {
				tt.Fatal(err)
			} else {
				tt.Log("secret entry cleartext", string(cleartext.Cleartext))
			}
		})
	}
}
