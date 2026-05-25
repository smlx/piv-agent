package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/smlx/piv-agent/internal/age"
	"github.com/smlx/piv-agent/internal/piv"
	"github.com/smlx/piv-agent/internal/pinentry"
	"github.com/smlx/piv-agent/internal/securitykey"
)

type GenerateSeedsCmd struct{}

func (c *GenerateSeedsCmd) Run(cli *CLI) error {
	l := slog.New(slog.NewTextHandler(
		os.Stderr,
		&slog.HandlerOptions{Level: slog.LevelDebug}))
	p := piv.New(l, pinentry.New("pinentry"))
	securityKeys, err := p.SecurityKeys()
	if err != nil {
		return fmt.Errorf("couldn't get security keys: %v", err)
	}

	if len(securityKeys) == 0 {
		return fmt.Errorf("no security keys found")
	}

	outDir, err := c.getOutputDir()
	if err != nil {
		return err
	}

	existingSeeds, err := c.loadExistingSeeds(l, outDir)
	if err != nil {
		return err
	}

	for _, k := range securityKeys {
		if err := c.processKey(k, existingSeeds, outDir); err != nil {
			return err
		}
	}
	return nil
}

func (c *GenerateSeedsCmd) getOutputDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("couldn't get user config dir: %v", err)
	}
	outDir := filepath.Join(configDir, "credstore", "seeds")

	if err := os.MkdirAll(outDir, 0700); err != nil {
		return "", fmt.Errorf("couldn't create out dir: %v", err)
	}

	return outDir, nil
}

func (c *GenerateSeedsCmd) loadExistingSeeds(
	l *slog.Logger,
	outDir string,
) (map[[8]byte][64]byte, error) {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return nil, fmt.Errorf("couldn't read out dir: %v", err)
	}
	existingSeeds := make(map[[8]byte][64]byte)
	for _, entry := range entries {
		if entry.IsDir() {
			l.Warn("directory in seed dir. ignoring.",
				slog.String("dirname", entry.Name()))
			continue
		}
		fileIDDecoded, err := hex.DecodeString(entry.Name())
		if err != nil || len(fileIDDecoded) != 8 {
			l.Warn("file with invalid name in seed dir. ignoring.",
				slog.String("filename", entry.Name()))
			continue
		}
		fileID := [8]byte(fileIDDecoded)
		seedPath := filepath.Join(outDir, entry.Name())
		cmd := exec.Command(
			"systemd-creds",
			"decrypt",
			"--user",
			fmt.Sprintf("--name=seeds_%s", entry.Name()),
			seedPath,
			"-")
		seedDecoded, err := cmd.Output()
		if err != nil || len(seedDecoded) != 64 {
			l.Warn("file with invalid contents in seed dir. ignoring.",
				slog.String("filename", entry.Name()))
			continue
		}
		seed := [64]byte(seedDecoded)
		existingSeeds[fileID] = seed
	}
	return existingSeeds, nil
}

func (c *GenerateSeedsCmd) processKey(
	k *securitykey.SecurityKey,
	existingSeeds map[[8]byte][64]byte,
	outDir string,
) error {
	dks, err := k.DecryptingKeys()
	if err != nil {
		return fmt.Errorf("couldn't get decrypting keys: %v", err)
	}
	for _, cryptoKey := range dks {
		keyTag, err := piv.KeyTag(cryptoKey.Public.(*ecdsa.PublicKey))
		if err != nil {
			return fmt.Errorf("couldn't get key tag: %v", err)
		}

		var seedExists bool
		for existingFileID, existingSeed := range existingSeeds {
			mlkemKey, err := mlkem.NewDecapsulationKey768(existingSeed[:])
			if err != nil {
				continue
			}
			expectedFileID := age.CalculateFileID(mlkemKey, keyTag)
			if bytes.Equal(expectedFileID, existingFileID[:]) {
				seedExists = true
				break
			}
		}

		slotKey := cryptoKey.SlotSpec.Slot.Key
		if seedExists {
			proceed, err := c.promptOverwrite(k, slotKey)
			if err != nil {
				return err
			}
			if !proceed {
				continue
			}
		}

		if err := c.generateAndSaveSeed(k, slotKey, keyTag, outDir); err != nil {
			return err
		}
	}
	return nil
}

func (c *GenerateSeedsCmd) promptOverwrite(
	k *securitykey.SecurityKey,
	slotKey uint32,
) (bool, error) {
	fmt.Printf("# WARNING: A seed already exists for %s serial %d slot %x.\n",
		k.Card(), k.Serial(), slotKey)
	fmt.Print("Do you want to generate an additional seed for this slot? [y/N]: ")
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("couldn't read prompt response: %v", err)
	}
	response = strings.ToLower(strings.TrimSpace(response))
	if response != "y" && response != "yes" {
		fmt.Println("# Skipping...")
		return false, nil
	}
	return true, nil
}

func (c *GenerateSeedsCmd) generateAndSaveSeed(
	k *securitykey.SecurityKey,
	slotKey uint32,
	keyTag [4]byte,
	outDir string,
) error {
	seed := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return fmt.Errorf("couldn't generate seed: %v", err)
	}

	mlkemKey, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return fmt.Errorf("couldn't generate ML-KEM decapsulation key: %v", err)
	}

	fileID := age.CalculateFileID(mlkemKey, keyTag)

	filename := hex.EncodeToString(fileID)
	outPath := filepath.Join(outDir, filename)

	cmd := exec.Command("systemd-creds", "encrypt", "--user",
		fmt.Sprintf("--name=seeds_%s", filename), "-", outPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("couldn't create stdin pipe for systemd-creds: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("couldn't start systemd-creds encrypt: %v", err)
	}

	if _, err := stdin.Write(seed); err != nil {
		return fmt.Errorf("couldn't write seed to systemd-creds: %v", err)
	}
	stdin.Close()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("systemd-creds encrypt failed: %v", err)
	}

	identity, err := age.NewIdentity(
		k.Serial(), byte(slotKey), keyTag, [8]byte(fileID)).Encode()
	if err != nil {
		return fmt.Errorf("couldn't encode identity: %v", err)
	}

	fmt.Printf("# Hardware-bound Identity for %s serial %d slot %x\n",
		k.Card(), k.Serial(), slotKey)
	fmt.Printf("# TPM-sealed seed written to %s\n", outPath)
	fmt.Printf("%s\n\n", identity)
	return nil
}
