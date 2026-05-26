package age_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"go.uber.org/mock/gomock"

	"github.com/smlx/piv-agent/internal/age"
)

func TestHandleIdentity(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	mockKey := NewMockECDHKey(ctrl)
	mockKey.EXPECT().Public().Return(&priv.PublicKey).AnyTimes()
	mockKey.EXPECT().ECDH(gomock.Any()).DoAndReturn(func(peer *ecdh.PublicKey) ([]byte, error) {
		ecdhPriv, err := priv.ECDH()
		if err != nil {
			return nil, err
		}
		return ecdhPriv.ECDH(peer)
	}).AnyTimes()

	mockFetcher := func(fileID [8]byte) ([]byte, error) {
		seed := make([]byte, 64) // valid seed length
		return seed, nil
	}

	handler := age.HandleIdentity(nil, mockFetcher)

	// Create valid 18-byte identity data
	data := make([]byte, 18)
	data[0] = 1                                  // Version 1
	binary.BigEndian.PutUint32(data[1:5], 12345) // Serial
	data[5] = 1                                  // SlotID
	// The rest (keyTag [6:10], fileID [10:18]) are zeros, which is fine for the mock.

	ident, err := handler(data)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if ident == nil {
		t.Fatal("expected an identity, got nil")
	}
}

func TestHandleIdentityInvalidLength(t *testing.T) {
	handler := age.HandleIdentity(nil, nil)

	// Too short
	_, err := handler([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for invalid data length, got nil")
	}
}

func TestHandleRecipientInvalidData(t *testing.T) {
	handler := age.HandleRecipient()

	// Pass arbitrary invalid data to ensure the handler is wired up
	_, err := handler([]byte("invalid-recipient-data"))
	if err == nil {
		t.Fatal("expected error for invalid recipient data, got nil")
	}
}
