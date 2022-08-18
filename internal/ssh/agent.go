package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/smlx/piv-agent/internal/keyservice/piv"
	"github.com/smlx/piv-agent/internal/notify"
	pinentry "github.com/smlx/piv-agent/internal/pinentry"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// retries is the passphrase attempt limit when decrypting SSH keyfiles
const retries = 3

// Agent implements the crypto/ssh Agent interface
// https://pkg.go.dev/golang.org/x/crypto/ssh/agent#Agent
type Agent struct {
	mu          sync.Mutex
	piv         *piv.KeyService
	log         *zap.Logger
	pinentry    *pinentry.PINEntry
	loadKeyfile bool
	cancel      context.CancelFunc
}

// ErrNotImplemented is returned from any unimplemented method.
var ErrNotImplemented = errors.New("not implemented in piv-agent")

// ErrUnknownKey is returned when a signature is requested for an unknown key.
var ErrUnknownKey = errors.New("requested signature of unknown key")

// passphrases caches passphrases for keyfiles
var passphrases = map[string][]byte{}

// NewAgent returns a new Agent.
func NewAgent(p *piv.KeyService, log *zap.Logger,
	loadKeyfile bool, cancel context.CancelFunc) *Agent {
	return &Agent{piv: p, log: log, loadKeyfile: loadKeyfile, cancel: cancel}
}

// List returns the identities known to the agent.
func (a *Agent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// get security key identities first
	ski, err := a.securityKeyIDs()
	if err != nil {
		return nil, fmt.Errorf("couldn't get token identities: %w", err)
	}
	// then key file identities
	if !a.loadKeyfile {
		return ski, err
	}
	kfi, err := a.keyFileIDs()
	if err != nil {
		return nil, fmt.Errorf("couldn't get keyfile identities: %w", err)
	}
	return append(ski, kfi...), nil
}

// returns the identities from hardware tokens
func (a *Agent) securityKeyIDs() ([]*agent.Key, error) {
	var keys []*agent.Key
	securityKeys, err := a.piv.SecurityKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get security keys: %v", err)
	}
	for _, k := range securityKeys {
		for _, s := range k.SigningKeys() {
			keys = append(keys, &agent.Key{
				Format:  s.PubSSH.Type(),
				Blob:    s.PubSSH.Marshal(),
				Comment: k.Comment(&s.SlotSpec),
			})
		}
	}
	return keys, nil
}

// returns the identities from keyfiles on disk
func (a *Agent) keyFileIDs() ([]*agent.Key, error) {
	var keys []*agent.Key
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(home, ".ssh/id_ed25519.pub")
	pubBytes, err := os.ReadFile(keyPath)
	if err != nil {
		a.log.Debug("couldn't load keyfile", zap.String("path", keyPath),
			zap.Error(err))
		return keys, nil
	}
	pubKey, _, _, _, err := gossh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		a.log.Debug("couldn't parse keyfile", zap.String("path", keyPath),
			zap.Error(err))
		return keys, nil
	}
	keys = append(keys, &agent.Key{
		Format:  pubKey.Type(),
		Blob:    pubKey.Marshal(),
		Comment: keyPath,
	})
	return keys, nil
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (a *Agent) Sign(key gossh.PublicKey, data []byte) (*gossh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
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

func (a *Agent) signWithSigners(key gossh.PublicKey, data []byte, signers []gossh.Signer) (*gossh.Signature, error) {
	for _, s := range signers {
		if !bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			continue
		}
		// (possibly) send a notification
		cancel := notify.Touch(a.log)
		defer cancel()
		// perform signature
		a.log.Debug("signing",
			zap.Binary("public key bytes", s.PublicKey().Marshal()))
		return s.Sign(rand.Reader, data)
	}
	return nil, fmt.Errorf("%w: %v", ErrUnknownKey, key)
}

// Add adds a private key to the agent.
func (a *Agent) Add(key agent.AddedKey) error {
	return ErrNotImplemented
}

// Remove removes all identities with the given public key.
func (a *Agent) Remove(key gossh.PublicKey) error {
	return ErrNotImplemented
}

// RemoveAll removes all identities.
// This is implemented by causing piv-agent to exit.
func (a *Agent) RemoveAll() error {
	a.cancel()
	return nil
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
func (a *Agent) Signers() ([]gossh.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
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
func (a *Agent) tokenSigners() ([]gossh.Signer, error) {
	var signers []gossh.Signer
	securityKeys, err := a.piv.SecurityKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get security keys: %v", err)
	}
	for _, k := range securityKeys {
		for _, s := range k.SigningKeys() {
			privKey, err := k.PrivateKey(&s.CryptoKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't get private key for slot %x: %v",
					s.SlotSpec.Slot.Key, err)
			}
			s, err := gossh.NewSignerFromKey(privKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't get signer for key: %v", err)
			}
			a.log.Debug("loaded signing key from security key",
				zap.Binary("public key bytes", s.PublicKey().Marshal()))
			signers = append(signers, s)
		}
	}
	return signers, nil
}

// doDecrypt prompts for a passphrase via pinentry and uses the passphrase to
// decrypt the given private key
func (a *Agent) doDecrypt(keyPath string,
	pub gossh.PublicKey, priv []byte) (gossh.Signer, error) {
	var passphrase []byte
	var signer gossh.Signer
	var err error
	for i := 0; i < retries; i++ {
		passphrase = passphrases[string(pub.Marshal())]
		if passphrase == nil {
			fingerprint := gossh.FingerprintSHA256(pub)
			passphrase, err = a.pinentry.GetPassphrase(
				fmt.Sprintf("%s %s %s", keyPath, fingerprint[:25], fingerprint[25:]),
				fingerprint, retries-i)
			if err != nil {
				return nil, err
			}
		}
		signer, err = gossh.ParsePrivateKeyWithPassphrase(priv, passphrase)
		if err == nil {
			a.log.Debug("loaded key from disk",
				zap.Binary("public key bytes", signer.PublicKey().Marshal()))
			passphrases[string(signer.PublicKey().Marshal())] = passphrase
			return signer, nil
		}
	}
	return nil, fmt.Errorf("couldn't decrypt and parse private key %v", err)
}

// get signers for all keys stored in files on disk
func (a *Agent) keyfileSigners() ([]gossh.Signer, error) {
	var signers []gossh.Signer
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(home, ".ssh/id_ed25519")
	priv, err := os.ReadFile(keyPath)
	if err != nil {
		a.log.Debug("couldn't load keyfile", zap.String("path", keyPath),
			zap.Error(err))
		return signers, nil
	}
	signer, err := gossh.ParsePrivateKey(priv)
	if err != nil {
		pmErr, ok := err.(*gossh.PassphraseMissingError)
		if !ok {
			return nil, err
		}
		signer, err = a.doDecrypt(keyPath, pmErr.PublicKey, priv)
		if err != nil {
			return nil, err
		}
	}
	signers = append(signers, signer)
	return signers, nil
}
