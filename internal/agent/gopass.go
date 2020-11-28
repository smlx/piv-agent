package agent

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"fmt"

	"github.com/go-piv/piv-go/piv"
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
func (a *Agent) SharedKey(recipient []byte, peer crypto.PublicKey) ([]byte, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	sshKeySpecs, err := a.tokenSSHKeySpecs()
	if err != nil {
		return nil, fmt.Errorf("couldn't get token keys: %w", err)
	}
	for _, sks := range sshKeySpecs {
		if bytes.Equal(recipient, ssh.MarshalAuthorizedKey(sks.PublicKey)) {
			// get the slot private key
			privKey, err := sks.SecurityKey.Key.PrivateKey(
				sks.KeySpec.Slot,
				sks.PublicKey.(ssh.CryptoPublicKey).CryptoPublicKey(),
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
	keyfileSpecs, err := a.keyfileSpecs()
	if err != nil {
		return nil, fmt.Errorf("couldn't get keyfile keys: %w", err)
	}
	for _, ks := range keyfileSpecs {
		if bytes.Equal(recipient, ssh.MarshalAuthorizedKey(ks.PublicKey)) {
			// TODO
		}
	}
	return nil, fmt.Errorf("couldn't find matching key")
}
