package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gen2brain/beeep"
	"github.com/go-piv/piv-go/piv"
	"github.com/smlx/piv-agent/internal/token"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Agent implements the Agent interface
// https://pkg.go.dev/golang.org/x/crypto/ssh/agent#Agent
type Agent struct {
	securityKeys []token.SecurityKey
	mutex        sync.Mutex
	log          *zap.Logger
	loadKeyfile  bool
}

// ErrNotImplemented is returned from any unimplemented method.
var ErrNotImplemented = errors.New("not implemented in piv-agent")

// ErrUnknownKey is returned when a signature is requested for an unknown key.
var ErrUnknownKey = errors.New("requested signature of unknown key")

// passphrases caches passphrases for keyfiles
var passphrases = map[string][]byte{}

// New returns a new Agent.
func New(log *zap.Logger, loadKeyfile bool) *Agent {
	return &Agent{log: log, loadKeyfile: loadKeyfile}
}

// reopenSecurityKeys closes and attempts to re-open all avalable security keys
func (a *Agent) reopenSecurityKeys() error {
	for _, sk := range a.securityKeys {
		_ = sk.Key.Close()
	}
	sks, err := token.List(a.log)
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
	// get token identities first
	tl, err := a.tokenList()
	if err != nil {
		return nil, fmt.Errorf("couldn't get token identities: %w", err)
	}
	if !a.loadKeyfile {
		return tl, err
	}
	kl, err := a.keyfileList()
	if err != nil {
		return nil, fmt.Errorf("couldn't get keyfile identities: %w", err)
	}
	return append(tl, kl...), nil
}

// returns the identities from hardware tokens
func (a *Agent) tokenList() ([]*agent.Key, error) {
	sshKeySpecs, err := token.SSHKeySpecs(a.securityKeys)
	if err != nil || len(a.securityKeys) == 0 {
		a.log.Debug("reopening security keys", zap.Error(err),
			zap.Int("number of security keys", len(a.securityKeys)))
		err = a.reopenSecurityKeys()
		if err != nil {
			return nil, fmt.Errorf("couldn't reopen security keys: %w", err)
		}
	}
	var keys []*agent.Key
	if len(a.securityKeys) > 0 {
		if sshKeySpecs == nil {
			sshKeySpecs, err = token.SSHKeySpecs(a.securityKeys)
			if err != nil {
				return nil, fmt.Errorf("couldn't get public SSH keys: %w", err)
			}
		}
		for _, sks := range sshKeySpecs {
			keys = append(keys, &agent.Key{
				Format: sks.PubKey.Type(),
				Blob:   sks.PubKey.Marshal(),
				Comment: fmt.Sprintf(
					`Security Key "%s" #%d PIV Slot %x`,
					sks.Card,
					sks.Serial,
					sks.Slot.Key),
			})
		}
	}
	return keys, nil
}

// returns the identities from keyfiles on disk
func (a *Agent) keyfileList() ([]*agent.Key, error) {
	var pkss []*agent.Key
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(home, ".ssh/id_ed25519.pub")
	pubBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		a.log.Debug("couldn't load keyfile", zap.String("path", keyPath),
			zap.Error(err))
		return pkss, nil
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		a.log.Debug("couldn't parse keyfile", zap.String("path", keyPath),
			zap.Error(err))
		return pkss, nil
	}
	pkss = append(pkss, &agent.Key{
		Format:  pubKey.Type(),
		Blob:    pubKey.Marshal(),
		Comment: keyPath,
	})
	return pkss, nil
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	// try token keys first
	ts, err := a.tokenSigners()
	if err != nil {
		return nil, fmt.Errorf("couldn't get token signers: %w", err)
	}
	sig, err := a.signWithSigners(key, data, ts)
	if err != nil {
		if !errors.Is(err, ErrUnknownKey) || !a.loadKeyfile {
			return nil, err
		}
	} else {
		return sig, nil
	}
	// fall back to keyfile keys
	ks, err := a.keyfileSigners()
	if err != nil {
		return nil, fmt.Errorf("couldn't get keyfile signers: %w", err)
	}
	return a.signWithSigners(key, data, ks)
}

func (a *Agent) signWithSigners(key ssh.PublicKey, data []byte, signers []ssh.Signer) (*ssh.Signature, error) {
	for _, s := range signers {
		if !bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			continue
		}
		// (possibly) send a notification
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		touchNotify(ctx)
		// perform signature
		a.log.Debug("signing",
			zap.Binary("public key bytes", s.PublicKey().Marshal()))
		return s.Sign(rand.Reader, data)
	}
	return nil, fmt.Errorf("%w: %v", ErrUnknownKey, key)
}

func touchNotify(ctx context.Context) {
	timer := time.NewTimer(8 * time.Second)
	go func() {
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
			beeep.Alert("Security Key Agent", "Waiting for touch...", "")
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
	ts, err := a.tokenSigners()
	if err != nil {
		return nil, fmt.Errorf("couldn't get token signers: %w", err)
	}
	if !a.loadKeyfile {
		return ts, nil
	}
	ks, err := a.keyfileSigners()
	if err != nil {
		return nil, fmt.Errorf("couldn't get keyfile signers: %w", err)
	}
	return append(ts, ks...), nil
}

// get signers for all keys stored in hardware tokens
func (a *Agent) tokenSigners() ([]ssh.Signer, error) {
	var signers []ssh.Signer
	sshKeySpecs, err := token.SSHKeySpecs(a.securityKeys)
	if err != nil {
		return nil, fmt.Errorf("couldn't get public keys: %w", err)
	}
	for _, sk := range a.securityKeys {
		for _, sks := range sshKeySpecs {
			privKey, err := sk.Key.PrivateKey(
				sks.Slot,
				sks.PubKey.(ssh.CryptoPublicKey).CryptoPublicKey(),
				piv.KeyAuth{PINPrompt: pinEntry(&sk)},
			)
			if err != nil {
				return nil, fmt.Errorf("couldn't get private key for slot %x: %w",
					sks.Slot.Key, err)
			}
			s, err := ssh.NewSignerFromKey(privKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't get signer for key: %w", err)
			}
			a.log.Debug("loaded key from card",
				zap.Binary("public key bytes", s.PublicKey().Marshal()))
			signers = append(signers, s)
		}
	}
	return signers, nil
}

// get signers for all keys stored in files on disk
func (a *Agent) keyfileSigners() ([]ssh.Signer, error) {
	var signers []ssh.Signer
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(home, ".ssh/id_ed25519")
	privBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		a.log.Debug("couldn't load keyfile", zap.String("path", keyPath),
			zap.Error(err))
		return signers, nil
	}
	signer, err := ssh.ParsePrivateKey(privBytes)
	if err != nil {
		pmErr, ok := err.(*ssh.PassphraseMissingError)
		if !ok {
			return nil, err
		}
		passphrase := passphrases[string(pmErr.PublicKey.Marshal())]
		if passphrase == nil {
			passphrase, err = getPassphrase(keyPath,
				string(ssh.FingerprintSHA256(pmErr.PublicKey)))
			if err != nil {
				return nil, err
			}
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(privBytes, passphrase)
		if err != nil {
			return nil, err
		}
		a.log.Debug("loaded key from disk",
			zap.Binary("public key bytes", signer.PublicKey().Marshal()))
		passphrases[string(signer.PublicKey().Marshal())] = passphrase
	}
	signers = append(signers, signer)
	return signers, nil
}
