package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gen2brain/beeep"
	"github.com/go-piv/piv-go/piv"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Agent implements the Agent interface
// https://pkg.go.dev/golang.org/x/crypto/ssh/agent#Agent
type Agent struct {
	securityKeys []securityKey
	mutex        sync.Mutex
	log          *zap.Logger
}

// ErrNotImplemented is returned from any unimplemented method.
var ErrNotImplemented = errors.New("not implemented in piv-agent")

// reopenSecurityKeys closes and attempts to re-open all avalable security keys
func (a *Agent) reopenSecurityKeys() error {
	for _, sk := range a.securityKeys {
		_ = sk.key.Close()
	}
	sks, err := getAllSecurityKeys(a.log)
	if err != nil {
		return fmt.Errorf("couldn't get all security keys: %w", err)
	}
	a.securityKeys = sks
	return nil
}

// List returns the identities known to the agent.
func (a *Agent) List() ([]*agent.Key, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	// try to get the list of SSH public keys, reopen the security keys on error
	pubKeySpecs, err := getSSHPubKeys(a.securityKeys)
	if err != nil || len(a.securityKeys) == 0 {
		a.log.Debug("reopening security keys", zap.Error(err),
			zap.Int("number of security keys", len(a.securityKeys)))
		err = a.reopenSecurityKeys()
		if err != nil {
			return nil, fmt.Errorf("couldn't reload security keys: %w", err)
		}
	}
	pubKeySpecs, err = getSSHPubKeys(a.securityKeys)
	if err != nil || len(a.securityKeys) == 0 {
		return nil, fmt.Errorf("couldn't get public SSH keys: %w", err)
	}
	var pkss []*agent.Key
	for _, pks := range pubKeySpecs {
		pkss = append(pkss, &agent.Key{
			Format: pks.pubKey.Type(),
			Blob:   pks.pubKey.Marshal(),
			Comment: fmt.Sprintf(
				`Security Key "%s" #%d PIV Slot %x`,
				pks.card,
				pks.serial,
				pks.slot.Key),
		})
	}
	return pkss, nil
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	signers, err := a.signers()
	if err != nil {
		return nil, fmt.Errorf("couldn't get signers: %w", err)
	}
	for _, s := range signers {
		if !bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			continue
		}
		// (possibly) send a notification
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		touchNotify(ctx)
		// perform signature
		return s.Sign(rand.Reader, data)
	}
	return nil, fmt.Errorf("requested signature of unknown key: %v", key)
}

func touchNotify(ctx context.Context) {
	timer := time.NewTimer(4 * time.Second)
	go func() {
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
			beeep.Notify("Security Key Agent", "Waiting for touch...", "")
		}
	}()
}

// Add adds a private key to the agent.
func (a *Agent) Add(key agent.AddedKey) error {
	return ErrNotImplemented
}

// Remove removes all identities with the given public key.
func (a *Agent) Remove(key ssh.PublicKey) error {
	return ErrNotImplemented
}

// RemoveAll removes all identities.
func (a *Agent) RemoveAll() error {
	return ErrNotImplemented
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an
// empty list.
func (a *Agent) Lock(passphrase []byte) error {
	return ErrNotImplemented
}

// Unlock undoes the effect of Lock
func (a *Agent) Unlock(passphrase []byte) error {
	return ErrNotImplemented
}

// Signers returns signers for all the known keys.
func (a *Agent) Signers() ([]ssh.Signer, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return a.signers()
}

func (a *Agent) signers() ([]ssh.Signer, error) {
	var signers []ssh.Signer
	sshPubKeySpecs, err := getSSHPubKeys(a.securityKeys)
	if err != nil {
		return nil, fmt.Errorf("couldn't get public keys: %w", err)
	}
	for _, sk := range a.securityKeys {
		for _, pubKeySpec := range sshPubKeySpecs {
			privKey, err := sk.key.PrivateKey(
				pubKeySpec.slot,
				pubKeySpec.pubKey.(ssh.CryptoPublicKey).CryptoPublicKey(),
				piv.KeyAuth{PINPrompt: pinEntry(&sk)},
			)
			if err != nil {
				return nil, fmt.Errorf("couldn't get private key for slot %x: %w",
					pubKeySpec.slot.Key, err)
			}
			s, err := ssh.NewSignerFromKey(privKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't get signer for key: %w", err)
			}
			signers = append(signers, s)
		}
	}
	return signers, nil
}
