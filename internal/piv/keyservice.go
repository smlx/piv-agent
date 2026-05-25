// Package piv implements the PIV keyservice.
package piv

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	pivgo "github.com/go-piv/piv-go/v2/piv"
	"github.com/smlx/piv-agent/internal/age"
	"github.com/smlx/piv-agent/internal/pinentry"
	"github.com/smlx/piv-agent/internal/securitykey"
)

// KeyService represents a collection of tokens and slots accessed by the
// Personal Identity Verifaction card interface.
type KeyService struct {
	mu           sync.Mutex
	log          *slog.Logger
	pinentry     *pinentry.PINEntry
	securityKeys []*securitykey.SecurityKey
}

// ECDHKey implements ECDH using an underlying ECDSA key.
type ECDHKey struct {
	mu *sync.Mutex
	*pivgo.ECDSAPrivateKey
}

// ECDH wraps the underlying private key ECDH operation in a mutex.
func (k *ECDHKey) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.ECDSAPrivateKey.ECDH(peer)
}

// New constructs a PIV KeyService and returns it.
func New(l *slog.Logger, pe *pinentry.PINEntry) *KeyService {
	return &KeyService{
		log:      l,
		pinentry: pe,
	}
}

// KeyTag calculates the 4-byte truncated SHA-256 hash of the uncompressed
// P-256 point, per the age spec.
func KeyTag(pub crypto.PublicKey) ([4]byte, error) {
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return [4]byte{}, fmt.Errorf("public key is not ECDSA")
	}
	ecdhPub, err := ecdsaPub.ECDH()
	if err != nil {
		return [4]byte{}, fmt.Errorf("couldn't convert to ECDH: %v", err)
	}
	b := ecdhPub.Bytes()
	hash := sha256.Sum256(b)
	var tag [4]byte
	copy(tag[:], hash[:4])
	return tag, nil
}

// GetECDHKey returns an ECDHKey associated with the given hardware device, slot, and key tag.
func (p *KeyService) GetECDHKey(serial uint32, slotID uint32, keyTag [4]byte) (age.ECDHKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	securityKeys, err := p.getSecurityKeys()
	if err != nil {
		return nil, fmt.Errorf("couldn't get security keys: %v", err)
	}
	for _, sk := range securityKeys {
		if sk.Serial() != serial {
			continue
		}
		cks, err := sk.CryptoKeys()
		if err != nil {
			return nil, fmt.Errorf("couldn't get crypto keys: %v", err)
		}
		for _, cryptoKey := range cks {
			if cryptoKey.SlotSpec.Slot.Key != slotID {
				continue
			}
			ecdsaPubKey, ok := cryptoKey.Public.(*ecdsa.PublicKey)
			if !ok {
				continue
			}
			thisTag, err := KeyTag(ecdsaPubKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't get key tag: %v", err)
			}
			if thisTag != keyTag {
				return nil, fmt.Errorf("key tag mismatch")
			}
			privKey, err := sk.PrivateKey(&cryptoKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't get private key from slot")
			}
			pivGoPrivKey, ok := privKey.(*pivgo.ECDSAPrivateKey)
			if !ok {
				return nil, fmt.Errorf("unexpected private key type: %T", privKey)
			}
			return &ECDHKey{mu: &p.mu, ECDSAPrivateKey: pivGoPrivKey}, nil
		}
	}
	return nil, fmt.Errorf("couldn't match hardware token or slot")
}

// CloseAll closes all security keys without checking for errors.
// This should be called to clean up connections to `pcscd`.
func (p *KeyService) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.log.Debug("closing security keys", slog.Int("count", len(p.securityKeys)))
	for _, k := range p.securityKeys {
		if err := k.Close(); err != nil {
			p.log.Debug("couldn't close key", slog.Any("error", err))
		}
	}
}

func (p *KeyService) reloadSecurityKeys(cards []string) error {
	// try to clean up and reset state
	for _, k := range p.securityKeys {
		_ = k.Close()
	}
	p.securityKeys = nil
	// load keys from scratch
	for _, card := range cards {
		sk, err := securitykey.New(card, p.pinentry)
		if err != nil {
			p.log.Warn("couldn't get SecurityKey", slog.String("card", card),
				slog.Any("error", err))
			continue
		}
		p.securityKeys = append(p.securityKeys, sk)
	}
	if len(p.securityKeys) == 0 {
		p.log.Warn("no valid security keys found")
	}
	return nil
}

func (p *KeyService) getSecurityKeys() ([]*securitykey.SecurityKey, error) {
	var err error
	// check if the card cache is valid, and reload if not
	cards, err := pivgo.Cards()
	if err != nil {
		return nil, fmt.Errorf("couldn't get cards: %v", err)
	}
	// check the cache size
	reload := len(cards) != len(p.securityKeys)
	if !reload {
		for _, sk := range p.securityKeys {
			// check the cache contents
			if !slices.ContainsFunc(cards, func(card string) bool {
				return card == sk.Card()
			}) {
				reload = true
				break
			}
			// check the keys are healthy
			if _, err = sk.AttestationCertificate(); err != nil {
				p.log.Debug("PIV KeyService: couldn't get AttestationCertificate()",
					slog.Any("error", err))
				reload = true
				break
			}
		}
	}
	if reload || len(p.securityKeys) == 0 {
		if err = p.reloadSecurityKeys(cards); err != nil {
			return nil, fmt.Errorf("couldn't reload security keys: %v", err)
		}
	}
	return p.securityKeys, nil
}

// SecurityKeys returns a slice containing all available security keys.
func (p *KeyService) SecurityKeys() ([]*securitykey.SecurityKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.getSecurityKeys()
}
