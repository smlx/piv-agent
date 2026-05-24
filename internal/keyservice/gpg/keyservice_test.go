package gpg_test

import (
	"encoding/hex"
	"log/slog"
	"os"
	"testing"

	"github.com/smlx/piv-agent/internal/keyservice/gpg"
	"go.uber.org/mock/gomock"
)

func hexMustDecode(s string) []byte {
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestGetSigner(t *testing.T) {
	var testCases = map[string]struct {
		path      string
		keygrip   []byte
		protected bool
	}{
		"unprotected key": {
			path:    "testdata/private/bar@example.com.gpg",
			keygrip: hexMustDecode("9128BB9362750577445FAAE9E737684EBB74FD6C"),
		},
		"protected key": {
			path:      "testdata/private/bar-protected@example.com.gpg",
			keygrip:   hexMustDecode("75B7C5A35213E71BA282F64317DDB90EC5C3FEE0"),
			protected: true,
		},
	}
	log := slog.New(slog.NewTextHandler(
		os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			defer ctrl.Finish()
			var mockPES = NewMockPINEntryService(ctrl)
			if tc.protected {
				mockPES.EXPECT().GetPassphrase(gomock.Any(), gomock.Any(), 3).
					Return([]byte("trustno1"), nil)
			}
			ks := gpg.New(log, mockPES, tc.path)
			if _, err := ks.GetSigner(tc.keygrip); err != nil {
				tt.Fatal(err)
			}
		})
	}
}
