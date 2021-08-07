package gpg

//go:generate mockgen -source=keyservice.go -destination=../../mock/mock_keyservice.go -package=mock

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/crypto/openpgp/packet"
)

// PINEntryService provides an interface to talk to a pinentry program.
type PINEntryService interface {
	GetPGPPassphrase(string) ([]byte, error)
}

// KeyService implements an interface for getting cryptographic keys from
// keyfiles on disk.
type KeyService struct {
	// cache passphrases used for decryption
	passphrases [][]byte
	privKeys    []*packet.PrivateKey
	log         *zap.Logger
	pinentry    PINEntryService
}

// New returns a keyservice initialised with keys found at path.
// Path can be a file or directory.
func New(l *zap.Logger, pe PINEntryService,
	path string) (*KeyService, error) {
	p, err := keyfilePrivateKeys(path)
	if err != nil {
		return nil, err
	}
	return &KeyService{
		privKeys: p,
		log:      l,
		pinentry: pe,
	}, nil
}

// Name returns the name of the keyservice.
func (*KeyService) Name() string {
	return "GPG Keyfile"
}

// HaveKey takes a list of keygrips, and returns a boolean indicating if any of
// the given keygrips were found, the found keygrip, and an error, if any.
func (g *KeyService) HaveKey(keygrips [][]byte) (bool, []byte, error) {
	for _, kg := range keygrips {
		key, err := g.getKey(kg)
		if err != nil {
			return false, nil, err
		}
		if key != nil {
			return true, kg, nil
		}
	}
	return false, nil, nil
}

// getKey returns a matching private RSA key if the keygrip matches. If a key
// is returned err will be nil. If no key is found, both values may be nil.
func (g *KeyService) getKey(keygrip []byte) (*rsa.PrivateKey, error) {
	var pass []byte
	var err error
	for _, k := range g.privKeys {
		pubKey, ok := k.PublicKey.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if !bytes.Equal(keygrip, keygripRSA(pubKey)) {
			continue
		}
		if k.Encrypted {
			// try existing passphrases
			for _, pass := range g.passphrases {
				if err = k.Decrypt(pass); err == nil {
					g.log.Debug("decrypted using cached passphrase",
						zap.String("fingerprint", k.KeyIdString()))
					break
				}
			}
		}
		if k.Encrypted {
			// ask for a passphrase
			pass, err = g.pinentry.GetPGPPassphrase(
				fmt.Sprintf("%X %X %X %X", k.Fingerprint[:5], k.Fingerprint[5:10],
					k.Fingerprint[10:15], k.Fingerprint[15:]))
			if err != nil {
				return nil, fmt.Errorf("couldn't get passphrase for key %s: %v",
					k.KeyIdString(), err)
			}
			g.passphrases = append(g.passphrases, pass)
			if err = k.Decrypt(pass); err != nil {
				return nil, fmt.Errorf("couldn't decrypt key %s: %v",
					k.KeyIdString(), err)
			}
			g.log.Debug("decrypted using passphrase",
				zap.String("fingerprint", k.KeyIdString()))
		}
		privKey, ok := k.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA key %s: %v",
				k.KeyIdString(), err)
		}
		return privKey, nil
	}
	return nil, nil
}

// GetSigner returns a crypto.Signer associated with the given keygrip.
func (g *KeyService) GetSigner(keygrip []byte) (crypto.Signer, error) {
	rsaPrivKey, err := g.getKey(keygrip)
	if err != nil {
		return nil, fmt.Errorf("couldn't getKey: %v", err)
	}
	return &RSAKey{rsa: rsaPrivKey}, nil
}

// GetDecrypter returns a crypto.Decrypter associated with the given keygrip.
func (g *KeyService) GetDecrypter(keygrip []byte) (crypto.Decrypter, error) {
	rsaPrivKey, err := g.getKey(keygrip)
	if err != nil {
		return nil, fmt.Errorf("couldn't getKey: %v", err)
	}
	return &RSAKey{rsa: rsaPrivKey}, nil
}
