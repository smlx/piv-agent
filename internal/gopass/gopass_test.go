package gopass_test

import (
	"fmt"
	"testing"
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
			fmt.Println("hi")
			fmt.Println(tc.input)
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
