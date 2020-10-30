package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/ssh"
)

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

func getSSHPubKeys(k *piv.YubiKey) ([]sshPubKeySpec, error) {
	var pubKeys []sshPubKeySpec
	for _, keySpec := range allKeySpec {
		cert, err := k.Certificate(keySpec.slot)
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
		})
	}
	return pubKeys, nil
}
