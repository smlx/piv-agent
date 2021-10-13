package gpg

//go:generate mockgen -source=keyservice.go -destination=../../mock/mock_keyservice.go -package=mock

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/crypto/openpgp/packet"
)

// retries is the passphrase attempt limit when decrypting GPG keyfiles
const retries = 3

// PINEntryService provides an interface to talk to a pinentry program.
type PINEntryService interface {
	GetPassphrase(string, string, int) ([]byte, error)
}

type privateKeyfile struct {
	uid  *packet.UserId
	keys []*packet.PrivateKey
}

// KeyService implements an interface for getting cryptographic keys from
// keyfiles on disk.
type KeyService struct {
	// cache passphrases used for keyfile decryption
	passphrases [][]byte
	privKeys    []privateKeyfile
	log         *zap.Logger
	pinentry    PINEntryService
}

// New returns a keyservice initialised with keys found at path.
// Path can be a file or directory.
func New(l *zap.Logger, pe PINEntryService, path string) *KeyService {
	p, err := keyfilePrivateKeys(path)
	if err != nil {
		l.Info("couldn't load keyfiles", zap.String("path", path), zap.Error(err))
	}
	return &KeyService{
		privKeys: p,
		log:      l,
		pinentry: pe,
	}
}

// Name returns the name of the keyservice.
func (*KeyService) Name() string {
	return "GPG Keyfile"
}

// doDecrypt prompts for a passphrase via pinentry and uses the passphrase to
// decrypt the given private key
func (g *KeyService) doDecrypt(k *packet.PrivateKey, uid string) error {
	var pass []byte
	var err error
	for i := 0; i < retries; i++ {
		pass, err = g.pinentry.GetPassphrase(
			fmt.Sprintf("UserID: %s\rFingerprint: %X %X %X %X", uid,
				k.Fingerprint[:5], k.Fingerprint[5:10], k.Fingerprint[10:15],
				k.Fingerprint[15:]),
			uid, retries-i)
		if err != nil {
			return fmt.Errorf("couldn't get passphrase for key %s: %v",
				k.KeyIdString(), err)
		}
		if err = k.Decrypt(pass); err == nil {
			g.passphrases = append(g.passphrases, pass)
			return nil
		}
	}
	return fmt.Errorf("couldn't decrypt key %s: %v", k.KeyIdString(), err)
}

// decryptPrivateKey decrypts the given private key.
// Returns nil if successful, or an error if the key could not be decrypted.
func (g *KeyService) decryptPrivateKey(k *packet.PrivateKey, uid string) error {
	var err error
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
		if err := g.doDecrypt(k, uid); err != nil {
			return err
		}
		g.log.Debug("decrypted using passphrase",
			zap.String("fingerprint", k.KeyIdString()))
	}
	return nil
}

// getRSAKey returns a matching private RSA key if the keygrip matches. If a key
// is returned err will be nil. If no key is found, both values may be nil.
func (g *KeyService) getRSAKey(keygrip []byte) (*rsa.PrivateKey, error) {
	for _, pk := range g.privKeys {
		for _, k := range pk.keys {
			pubKey, ok := k.PublicKey.PublicKey.(*rsa.PublicKey)
			if !ok {
				continue
			}
			pubKeygrip, err := keygripRSA(pubKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't get RSA keygrip: %v", err)
			}
			if !bytes.Equal(keygrip, pubKeygrip) {
				continue
			}
			err = g.decryptPrivateKey(k,
				fmt.Sprintf("%s (%s) <%s>",
					pk.uid.Name, pk.uid.Comment, pk.uid.Email))
			if err != nil {
				return nil, err
			}
			privKey, ok := k.PrivateKey.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("not an RSA key %s: %v",
					k.KeyIdString(), err)
			}
			return privKey, nil
		}
	}
	return nil, nil
}

// getECDSAKey returns a matching private ECDSA key if the keygrip matches. If
// a key is returned err will be nil. If no key is found, both values will be
// nil.
func (g *KeyService) getECDSAKey(keygrip []byte) (*ecdsa.PrivateKey, error) {
	for _, pk := range g.privKeys {
		for _, k := range pk.keys {
			pubKey, ok := k.PublicKey.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				continue
			}
			pubKeygrip, err := KeygripECDSA(pubKey)
			if err != nil {
				return nil, fmt.Errorf("couldn't get ECDSA keygrip: %v", err)
			}
			if !bytes.Equal(keygrip, pubKeygrip) {
				continue
			}
			err = g.decryptPrivateKey(k,
				fmt.Sprintf("%s (%s) <%s>",
					pk.uid.Name, pk.uid.Comment, pk.uid.Email))
			if err != nil {
				return nil, err
			}
			privKey, ok := k.PrivateKey.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("not an ECDSA key %s: %v",
					k.KeyIdString(), err)
			}
			return privKey, nil
		}
	}
	return nil, nil
}

// GetSigner returns a crypto.Signer associated with the given keygrip.
func (g *KeyService) GetSigner(keygrip []byte) (crypto.Signer, error) {
	rsaPrivKey, err := g.getRSAKey(keygrip)
	if err != nil {
		return nil, fmt.Errorf("couldn't getRSAKey: %v", err)
	}
	if rsaPrivKey != nil {
		return &RSAKey{rsa: rsaPrivKey}, nil
	}
	ecdsaPrivKey, err := g.getECDSAKey(keygrip)
	if err != nil {
		return nil, fmt.Errorf("couldn't getECDSAKey: %v", err)
	}
	if ecdsaPrivKey != nil {
		return ecdsaPrivKey, nil
	}
	return nil, fmt.Errorf("couldn't get signer for keygrip %X", keygrip)
}

// GetDecrypter returns a crypto.Decrypter associated with the given keygrip.
func (g *KeyService) GetDecrypter(keygrip []byte) (crypto.Decrypter, error) {
	rsaPrivKey, err := g.getRSAKey(keygrip)
	if err != nil {
		return nil, fmt.Errorf("couldn't getRSAKey: %v", err)
	}
	if rsaPrivKey != nil {
		return &RSAKey{rsa: rsaPrivKey}, nil
	}
	ecdsaPrivKey, err := g.getECDSAKey(keygrip)
	if err != nil {
		return nil, fmt.Errorf("couldn't getECDSAKey: %v", err)
	}
	if ecdsaPrivKey != nil {
		return &ECDHKey{ecdsa: ecdsaPrivKey}, nil
	}
	return nil, fmt.Errorf("couldn't get decrypter for keygrip %X", keygrip)
}
