package securitykey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/mlkem"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	pivgo "github.com/go-piv/piv-go/v2/piv"
	"github.com/smlx/piv-agent/internal/age"
	"golang.org/x/crypto/ssh"
)

var touchStringMap = map[pivgo.TouchPolicy]string{
	pivgo.TouchPolicyNever:  "never",
	pivgo.TouchPolicyAlways: "always",
	pivgo.TouchPolicyCached: "cached",
}

// TouchPolicyString returns the string representation of a TouchPolicy.
func TouchPolicyString(tp pivgo.TouchPolicy) string {
	if s, ok := touchStringMap[tp]; ok {
		return s
	}
	return "unknown"
}

// Comment returns a comment suitable for e.g. the SSH public key format
func (k *SecurityKey) Comment(ss *SlotSpec) string {
	return fmt.Sprintf("%v #%v, touch policy: %s", k.card, k.serial,
		TouchPolicyString(ss.TouchPolicy))
}

// StringsSSH returns an array of commonly formatted SSH keys as strings.
func (k *SecurityKey) StringsSSH() ([]string, error) {
	sks, err := k.SigningKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get signing keys: %v", err)
	}
	var ss []string
	for _, s := range sks {
		ss = append(ss, fmt.Sprintf("%s %s\n",
			strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(s.PubSSH)), "\n"),
			k.Comment(&s.SlotSpec)))
	}
	return ss, nil
}

// NonFatalErrors accumulates multiple non-fatal errors.
type NonFatalErrors []error

// Error implements the error interface.
func (e NonFatalErrors) Error() string {
	var msgs []string
	for _, err := range e {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, ", ")
}

// StringsAge returns an array of commonly formatted Age identities and
// recipients as strings.
func (k *SecurityKey) StringsAge(slotFilter []uint32) ([]string, error) {
	dks, err := k.DecryptingKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get decrypting keys: %v", err)
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("couldn't get user config dir: %v", err)
	}
	seedsDir := filepath.Join(configDir, "credstore", "seeds")

	var ss []string
	var errs NonFatalErrors
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	for _, cryptoKey := range dks {
		slotKey := cryptoKey.SlotSpec.Slot.Key
		if len(slotFilter) > 0 && !slices.Contains(slotFilter, slotKey) {
			continue
		}

		cert, err := k.Certificate(cryptoKey.SlotSpec.Slot)
		if err != nil {
			errs = append(errs, fmt.Errorf("couldn't get certificate for slot %x: %v", slotKey, err))
			continue
		}
		fileID, err := ExtractFileIDFromCert(cert)
		if err != nil {
			errs = append(errs, fmt.Errorf("couldn't extract file ID for slot %x: %v", slotKey, err))
			continue
		}
		if fileID == nil {
			continue
		}

		seedPath := filepath.Join(seedsDir, hex.EncodeToString(fileID))
		if _, err := os.Stat(seedPath); os.IsNotExist(err) {
			// seed doesn't exist locally, so this slot is unavailable on this machine.
			continue
		}

		cmd := exec.Command("systemd-creds", "decrypt", "--user",
			fmt.Sprintf("--name=seeds_%s", hex.EncodeToString(fileID)), seedPath, "-")
		seedBytes, err := cmd.Output()
		if err != nil || len(seedBytes) != 64 {
			errs = append(errs, fmt.Errorf("couldn't read or decrypt seed for slot %x: %v", slotKey, err))
			continue
		}
		mlkemKey, err := mlkem.NewDecapsulationKey768(seedBytes)
		if err != nil {
			errs = append(errs, fmt.Errorf("couldn't generate ML-KEM decapsulation key: %v", err))
			continue
		}

		keyTag, err := cryptoKey.KeyTag()
		if err != nil {
			errs = append(errs, fmt.Errorf("couldn't get key tag for slot %x: %v", slotKey, err))
			continue
		}
		ecdhPub, err := cryptoKey.Public.(*ecdsa.PublicKey).ECDH()
		if err != nil {
			errs = append(errs, fmt.Errorf("couldn't convert public key for slot %x: %v", slotKey, err))
			continue
		}

		expectedFileID := age.CalculateSeedFileID(mlkemKey, keyTag)
		if !bytes.Equal(expectedFileID, fileID) {
			errs = append(errs, fmt.Errorf("seed file ID mismatch for slot %x", slotKey))
			continue
		}

		identity, err := age.NewIdentity(
			k.Serial(), byte(slotKey), keyTag, [8]byte(fileID)).Encode()
		if err != nil {
			errs = append(errs, fmt.Errorf("couldn't encode identity for slot %x: %v", slotKey, err))
			continue
		}

		recipient := age.EncodeRecipient(
			mlkemKey.EncapsulationKey().Bytes(), ecdhPub.Bytes())

		ss = append(ss, fmt.Sprintf(
			"# Hardware Identity for %s serial %d slot %x",
			k.Card(), k.Serial(), slotKey))
		ss = append(ss, fmt.Sprintf("# Host name: %s", hostname))
		ss = append(ss, fmt.Sprintf(
			"# Seed file: %s", hex.EncodeToString(fileID)))
		ss = append(ss, fmt.Sprintf("# Recipient: %s", recipient))
		ss = append(ss, identity)
		ss = append(ss, "")
	}

	if len(errs) > 0 {
		return ss, errs
	}
	return ss, nil
}
