package agent

import (
	"fmt"

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
