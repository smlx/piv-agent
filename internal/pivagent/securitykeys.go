package pivagent

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"github.com/smlx/piv-agent/internal/key"
	"go.uber.org/zap"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/ssh"
)

// SecurityKeys returns a slice containing all security keys available.
func (p *PIVAgent) SecurityKeys() ([]key.Security, error) {
	var all []key.Security
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("couldn't get smart cards: %w", err)
	}
	var k *piv.YubiKey
	for _, card := range cards {
		k, err = piv.Open(card)
		if err != nil {
			p.log.Debug("couldn't open connection to security key",
				zap.String("card", card), zap.Error(err))
		} else {
			p.log.Debug("opened connection to security key", zap.String("card", card))
			serial, err := k.Serial()
			if err != nil {
				p.log.Warn("couldn't get serial for security key",
					zap.String("card", card), zap.Error(err))
				continue
			}
			signingKeys, err := signingKeys(k)
			all = append(all, key.Security{
				Card:        card,
				Key:         k,
				Serial:      serial,
				SigningKeys: signingKeys,
			})
		}
	}
	return all, nil
}

// signingKeys returns the signing keys available on the given SecurityKey.
func signingKeys(k *piv.YubiKey) ([]key.Sign, error) {
	var signingKeys []key.Sign
	for _, s := range key.SignSlots {
		cert, err := k.Certificate(s.Slot)
		if err != nil {
			if errors.Is(err, piv.ErrNotFound) {
				continue
			}
			return nil, fmt.Errorf("couldn't get certificate for slot %x: %w",
				s.Slot.Key, err)
		}
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid public key type: %T", cert.PublicKey)
		}
		pubSSH, err := ssh.NewPublicKey(cert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("couldn't convert public key: %w", err)
		}
		signingKeys = append(signingKeys, key.Sign{
			Public:   pubKey,
			PubSSH:      pubSSH,
			PubPGP:      packet.NewECDSAPublicKey(cert.NotBefore, pubKey),
			Slot:        s.Slot,
			TouchPolicy: s.TouchPolicy,
		})
	}
	return signingKeys, nil
}
