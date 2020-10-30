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
	"github.com/gopasspw/gopass/pkg/pinentry"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Agent implements the Agent interface
// https://pkg.go.dev/golang.org/x/crypto/ssh/agent#Agent
type Agent struct {
	securityKey *piv.YubiKey
	mutex       sync.Mutex
	serial      int
}

// ErrNotImplemented is returned from any unimplemented method.
var ErrNotImplemented = errors.New("not implemented in piv-agent")

// List returns the identities known to the agent.
func (a *Agent) List() ([]*agent.Key, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	// get the SSH keys from the security key
	pubKeySpecs, err := getSSHPubKeys(a.securityKey)
	if err != nil {
		return nil, fmt.Errorf("couldn't get SSH public keys: %w", err)
	}
	var pkss []*agent.Key
	for _, pks := range pubKeySpecs {
		pkss = append(pkss, &agent.Key{
			Format:  pks.pubKey.Type(),
			Blob:    pks.pubKey.Marshal(),
			Comment: fmt.Sprintf("YubiKey #%d PIV Slot %x", a.serial, pks.slot.Key),
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
	sshPubKeySpecs, err := getSSHPubKeys(a.securityKey)
	if err != nil {
		return nil, fmt.Errorf("couldn't get public keys: %w", err)
	}
	for _, pubKeySpec := range sshPubKeySpecs {
		privKey, err := a.securityKey.PrivateKey(
			pubKeySpec.slot,
			pubKeySpec.pubKey.(ssh.CryptoPublicKey).CryptoPublicKey(),
			piv.KeyAuth{PINPrompt: a.pinEntry},
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
	return signers, nil
}

func (a *Agent) pinEntry() (string, error) {
	p, err := pinentry.New()
	if err != nil {
		return "", fmt.Errorf("couldn't get pinentry client: %w", err)
	}
	defer p.Close()
	p.Set("title", "piv-agent PIN Prompt")
	r, err := a.securityKey.Retries()
	if err != nil {
		return "", fmt.Errorf("couldn't get retries for security key: %w", err)
	}
	p.Set("desc",
		fmt.Sprintf("serial number: %d, attempts remaining: %d", a.serial, r))
	p.Set("prompt", "Please enter your PIN:")
	pin, err := p.GetPin()
	return string(pin), err
}
