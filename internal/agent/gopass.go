package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"go.uber.org/zap"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// These functions are helpers for the gopass.Crypto implementation.

// PublicKeys is similar to List(), except that the format returned is
// ssh.PublicKey.
func (a *Agent) PublicKeys() ([]ssh.PublicKey, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	sshKeySpecs, err := a.tokenSSHKeySpecs()
	if err != nil {
		return nil, fmt.Errorf("couldn't get token keys: %w", err)
	}
	keyfileSpecs, err := a.keyfileSpecs()
	if err != nil {
		return nil, fmt.Errorf("couldn't get keyfile keys: %w", err)
	}

	var pubKeys []ssh.PublicKey
	for _, sks := range sshKeySpecs {
		pubKeys = append(pubKeys, sks.PublicKey)
	}
	for _, ks := range keyfileSpecs {
		pubKeys = append(pubKeys, ks.PublicKey)
	}
	return pubKeys, nil
}

// SharedKey performs ECDH to return a shared secret key.
// The recipient is the public key associated with a private key available on
// the agent. And the peer is the public key used to generate the shared secret.
func (a *Agent) SharedKey(recipient, peer crypto.PublicKey) ([]byte, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	sk, err := a.tokenSharedKey(recipient, peer)
	if err == nil {
		return sk, nil
	}
	a.log.Debug("no token key match", zap.Error(err))
	sk, err = a.keyfileSharedKey(recipient, peer)
	if err == nil {
		return sk, nil
	}
	a.log.Debug("no keyfile key match", zap.Error(err))
	return nil, fmt.Errorf("couldn't find local key matching recipient")
}

func (a *Agent) tokenSharedKey(recipient, peer crypto.PublicKey) ([]byte, error) {
	sshKeySpecs, err := a.tokenSSHKeySpecs()
	if err != nil {
		return nil, fmt.Errorf("couldn't get token keys: %w", err)
	}
	for _, sks := range sshKeySpecs {
		cPubKey, ok := sks.PublicKey.(ssh.CryptoPublicKey)
		if !ok {
			return nil, fmt.Errorf("couldn't cast to ssh.CryptoPublicKey")
		}
		ecdsaPubKey, ok := cPubKey.CryptoPublicKey().(*ecdsa.PublicKey)
		if !ok {
			continue // key type mismatch
		}
		if ecdsaPubKey.Equal(recipient) {
			// get the slot private key
			privKey, err := sks.SecurityKey.Key.PrivateKey(
				sks.KeySpec.Slot,
				cPubKey.CryptoPublicKey(),
				piv.KeyAuth{PINPrompt: pinEntry(&sks.SecurityKey)},
			)
			if err != nil {
				return nil, fmt.Errorf("couldn't get private key for slot %x: %w",
					sks.KeySpec.Slot, err)
			}
			ecPrivKey, ok := privKey.(*piv.ECDSAPrivateKey)
			if !ok {
				return nil, fmt.Errorf("couldn't cast slot private key")
			}
			ecPubKey, ok := peer.(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("couldn't cast peer public key")
			}
			// generate the shared secret
			return ecPrivKey.SharedKey(ecPubKey)
		}
	}
	return nil, fmt.Errorf("no matching token key")
}

func (a *Agent) keyfileSharedKey(recipient, peer crypto.PublicKey) ([]byte, error) {
	peerEdPubKey, ok := peer.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("couldn't cast peer public key to ed25519")
	}
	keyfileSpecs, err := a.keyfileSpecs()
	if err != nil {
		return nil, fmt.Errorf("couldn't get keyfile keys: %w", err)
	}
	for _, ks := range keyfileSpecs {
		cPubKey, ok := ks.PublicKey.(ssh.CryptoPublicKey)
		if !ok {
			return nil, fmt.Errorf("couldn't cast to ssh.CryptoPublicKey")
		}
		ed25519PubKey, ok := cPubKey.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			continue // key type mismatch
		}
		if ed25519PubKey.Equal(recipient) {
			// get the private key
			keyPath := strings.TrimSuffix(ks.Path, ".pub")
			privBytes, err := ioutil.ReadFile(keyPath)
			if err != nil {
				return nil, fmt.Errorf("coulnd't read private keyfile: %w", err)
			}
			privKey, err := ssh.ParseRawPrivateKey(privBytes)
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
				privKey, err = ssh.ParseRawPrivateKeyWithPassphrase(privBytes, passphrase)
				if err != nil {
					return nil, err
				}
				passphrases[string(ks.PublicKey.Marshal())] = passphrase
			}
			ed25519PrivKey, ok := privKey.(ed25519.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("couldn't cast private keyfile to ed25519")
			}
			sharedSecret, err := curve25519.X25519(ed25519PrivKey, peerEdPubKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't perform scalar multiplication: %w", err)
			}
			return sharedSecret, nil
		}
	}
	return nil, fmt.Errorf("no matching keyfile key")
}
