package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"github.com/gopasspw/gopass/pkg/pinentry"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type securityKey struct {
	card   string
	key    *piv.YubiKey
	serial uint32
}

func getAllSecurityKeys(log *zap.Logger) ([]securityKey, error) {
	var all []securityKey
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("couldn't get smart cards: %w", err)
	}
	var sk *piv.YubiKey
	for _, card := range cards {
		sk, err = piv.Open(card)
		if err != nil {
			log.Debug("couldn't open card", zap.String("card", card), zap.Error(err))
		} else {
			// cache serial
			serial, err := sk.Serial()
			if err != nil {
				log.Warn("couldn't get serial for card",
					zap.String("card", card), zap.Error(err))
				continue
			}
			all = append(all, securityKey{
				card:   card,
				key:    sk,
				serial: serial,
			})
		}
	}
	return all, nil
}

func getSecurityKey(card string) (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("couldn't get smart cards: %w", err)
	}
	if len(cards) > 1 {
		if card == "" {
			return nil, fmt.Errorf("please specify a smart card: %v", cards)
		}
		for i := range cards {
			if cards[i] == card {
				return piv.Open(card)
			}
		}
		return nil, fmt.Errorf("couldn't find specified smart card")
	}
	return piv.Open(cards[0])
}

func getSSHPubKeys(sks []securityKey) ([]sshPubKeySpec, error) {
	var pubKeys []sshPubKeySpec
	for _, sk := range sks {
		for _, keySpec := range allKeySpec {
			cert, err := sk.key.Certificate(keySpec.slot)
			if err != nil {
				if errors.Is(err, piv.ErrNotFound) {
					continue
				}
				return nil, fmt.Errorf("couldn't get certificate for slot %x: %w",
					keySpec.slot.Key, err)
			}
			_, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("invalid public key type: %T", cert.PublicKey)
			}
			pub, err := ssh.NewPublicKey(cert.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't convert public key: %w", err)
			}
			pubKeys = append(pubKeys, sshPubKeySpec{
				pubKey:      pub,
				slot:        keySpec.slot,
				touchPolicy: keySpec.touchPolicy,
				card:        sk.card,
				serial:      sk.serial,
			})
		}
	}
	return pubKeys, nil
}

func pinEntry(sk *securityKey) func() (string, error) {
	return func() (string, error) {
		p, err := pinentry.New()
		if err != nil {
			return "", fmt.Errorf("couldn't get pinentry client: %w", err)
		}
		defer p.Close()
		p.Set("title", "piv-agent PIN Prompt")
		r, err := sk.key.Retries()
		if err != nil {
			return "", fmt.Errorf("couldn't get retries for security key: %w", err)
		}
		p.Set("desc",
			fmt.Sprintf("serial number: %d, attempts remaining: %d", sk.serial, r))
		p.Set("prompt", "Please enter your PIN:")
		pin, err := p.GetPin()
		return string(pin), err
	}
}
