package gopass_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/smlx/piv-agent/internal/gopass"
	"github.com/smlx/piv-agent/internal/mock"
	"go.uber.org/zap"
)

//go:generate mockgen -source=gopass.go -destination ../mock/mock_gopass.go -package mock

func TestEncrypt(t *testing.T) {
	var testCases = map[string]struct {
		input  string
		expect string
	}{
		"case_description": {input: "foo", expect: "bar"},
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
			mockAgent.EXPECT().PublicKeys().Return()

			crypto := gopass.NewCrypto(mockAgent, exitTicker, log, "test")

			crypto.Encrypt()
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
