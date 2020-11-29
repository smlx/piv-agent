package gopass_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/smlx/piv-agent/internal/gopass"
	"github.com/smlx/piv-agent/internal/gopass/pb"
	"github.com/smlx/piv-agent/internal/mock"
	"go.uber.org/zap"
)

//go:generate mockgen -source=gopass.go -destination ../mock/mock_gopass.go -package mock

func TestEncrypt(t *testing.T) {
	var testCases = map[string]struct {
		plaintext  []byte
		recipients [][]byte
	}{
		"case_description": {
			plaintext: []byte("ACollectionOfDiplomaticHistorySince_1966_ToThe_PresentDay#"),
			recipients: [][]byte{
				[]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOK4b6vRLO6wHpPcy7Mh5ui7k5vIYl/KOGG2GgzNKghCXemPc6z3jHi6p49jbTzXhJzSQO3lt2ElDhdUvyBC5N8= scott@thinky"),
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

			crypto := gopass.NewCrypto(mockAgent, exitTicker, log, "test")

			ciphertext, err := crypto.Encrypt(context.TODO(), &pb.EncryptArgs{
				Plaintext:  tc.plaintext,
				Recipients: tc.recipients,
			})
			if err != nil {
				tt.Fatal(err)
			} else {
				tt.Log(base64.StdEncoding.EncodeToString(ciphertext.Ciphertext))
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	var testCases = map[string]struct {
		input  string
		expect string
	}{
		"case_description": {input: "foo", expect: "bar"},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			fmt.Println("hi")
			fmt.Println(tc.input)
		})
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	var testCases = map[string]struct {
		input  string
		expect string
	}{
		"case_description": {input: "foo", expect: "bar"},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			fmt.Println("hi")
			fmt.Println(tc.input)
		})
	}
}
