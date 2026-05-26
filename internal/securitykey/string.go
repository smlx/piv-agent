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

	"github.com/ProtonMail/go-crypto/openpgp"
	pivgo "github.com/go-piv/piv-go/v2/piv"
	"github.com/smlx/piv-agent/internal/age"
	"golang.org/x/crypto/ssh"
)

var touchStringMap = map[pivgo.TouchPolicy]string{
	pivgo.TouchPolicyNever:  "never",
	pivgo.TouchPolicyAlways: "always",
	pivgo.TouchPolicyCached: "cached",
}

// Entity wraps a synthesized openpgp.Entity and associates it with a
// SigningKey.
type Entity struct {
	openpgp.Entity
	CryptoKey
}

// Comment returns a comment suitable for e.g. the SSH public key format
func (k *SecurityKey) Comment(ss *SlotSpec) string {
	return fmt.Sprintf("%v #%v, touch policy: %s", k.card, k.serial,
		touchStringMap[ss.TouchPolicy])
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
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("couldn't get user config dir: %v", err)
	}
	seedsDir := filepath.Join(configDir, "credstore", "seeds")
	entries, err := os.ReadDir(seedsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("couldn't read seeds dir: %v", err)
	}

	type seedInfo struct {
		fileID   [8]byte
		mlkemKey *mlkem.DecapsulationKey768
	}
	var seeds []seedInfo

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fileID, err := hex.DecodeString(entry.Name())
		if err != nil || len(fileID) != 8 {
			continue
		}
		seedPath := filepath.Join(seedsDir, entry.Name())
		cmd := exec.Command(
			"systemd-creds",
			"decrypt",
			"--user",
			fmt.Sprintf("--name=seeds_%s", entry.Name()), seedPath, "-")
		seedBytes, err := cmd.Output()
		if err != nil || len(seedBytes) != 64 {
			continue
		}
		mlkemKey, err := mlkem.NewDecapsulationKey768(seedBytes)
		if err != nil {
			continue
		}
		seeds = append(seeds, seedInfo{
			fileID:   [8]byte(fileID),
			mlkemKey: mlkemKey,
		})
	}

	if len(seeds) == 0 {
		return nil, nil
	}
	dks, err := k.DecryptingKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get decrypting keys: %v", err)
	}

	var ss []string
	var errs NonFatalErrors
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	for _, cryptoKey := range dks {
		slotKey := cryptoKey.SlotSpec.Slot.Key
		// filter if necessary
		if len(slotFilter) > 0 && !slices.Contains(slotFilter, slotKey) {
			continue
		}
		// calculate the key tag
		keyTag, err := cryptoKey.KeyTag()
		if err != nil {
			errs = append(errs,
				fmt.Errorf("couldn't get key tag for slot %x: %v", slotKey, err))
			continue
		}
		// convert public key to ECDH for age recipient generation
		ecdhPub, err := cryptoKey.Public.(*ecdsa.PublicKey).ECDH()
		if err != nil {
			errs = append(errs,
				fmt.Errorf("couldn't convert public key for slot %x: %v", slotKey, err))
			continue
		}
		for _, seed := range seeds {
			// check if the seed file is bound to this slot
			expectedFileID := age.CalculateFileID(seed.mlkemKey, keyTag)
			if !bytes.Equal(expectedFileID, seed.fileID[:]) {
				continue
			}

			identity, err := age.NewIdentity(
				k.Serial(), byte(slotKey), keyTag, seed.fileID).Encode()
			if err != nil {
				errs = append(errs,
					fmt.Errorf("couldn't encode identity for slot %x: %v", slotKey, err))
				continue
			}

			recipient := age.EncodeRecipient(
				seed.mlkemKey.EncapsulationKey().Bytes(), ecdhPub.Bytes())

			ss = append(ss, fmt.Sprintf(
				"# Hardware Identity for %s serial %d slot %x",
				k.Card(), k.Serial(), slotKey))
			ss = append(ss, fmt.Sprintf("# Host name: %s", hostname))
			ss = append(ss, fmt.Sprintf(
				"# Seed file: %s", hex.EncodeToString(seed.fileID[:])))
			ss = append(ss, fmt.Sprintf("# Recipient: %s", recipient))
			ss = append(ss, identity)
			ss = append(ss, "")
		}
	}
	if len(errs) > 0 {
		return ss, errs
	}
	return ss, nil
}
