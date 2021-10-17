package securitykey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"strings"
	"time"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/ssh"
)

var touchStringMap = map[piv.TouchPolicy]string{
	piv.TouchPolicyNever:  "never",
	piv.TouchPolicyAlways: "always",
	piv.TouchPolicyCached: "cached",
}

// Entity wraps a synthesized openpgp.Entity and associates it with a
// SigningKey.
type Entity struct {
	openpgp.Entity
	CryptoKey
}

// Comment returns a comment suitable for e.g. the SSH public key format
func (k *SecurityKey) Comment(ss *SlotSpec) string {
	return fmt.Sprintf("%v #%v, touch policy: %s", k.card, k.serial,
		touchStringMap[ss.TouchPolicy])
}

// StringsSSH returns an array of commonly formatted SSH keys as strings.
func (k *SecurityKey) StringsSSH() []string {
	var ss []string
	for _, s := range k.SigningKeys() {
		ss = append(ss, fmt.Sprintf("%s %s\n",
			strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(s.PubSSH)), "\n"),
			k.Comment(&s.SlotSpec)))
	}
	return ss
}

func (k *SecurityKey) synthesizeEntity(ck *CryptoKey, now time.Time,
	name, email, comment string) (*openpgp.Entity, error) {
	cryptoPrivKey, err := k.PrivateKey(ck)
	if err != nil {
		return nil, fmt.Errorf("couldn't get private key: %v", err)
	}
	signer, ok := cryptoPrivKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is invalid type")
	}
	uid := packet.NewUserId(name, comment, email)
	if uid == nil {
		return nil, errors.InvalidArgumentError("invalid characters in user ID")
	}
	ecdsaPubKey, ok := ck.Public.(*ecdsa.PublicKey)
	if !ok {
		// TODO: handle ed25519 keys
		return nil, fmt.Errorf("not an ECDSA key")
	}
	pub := packet.NewECDSAPublicKey(now, ecdsaPubKey)
	priv := packet.NewSignerPrivateKey(now, signer)
	selfSignature := packet.Signature{
		CreationTime: now,
		SigType:      packet.SigTypePositiveCert,
		// TODO: determine the key type
		PubKeyAlgo:  packet.PubKeyAlgoECDSA,
		Hash:        crypto.SHA256,
		IssuerKeyId: &pub.KeyId,
		FlagsValid:  true,
		FlagSign:    true,
		FlagCertify: true,
	}
	err = selfSignature.SignUserId(uid.Id, pub, priv, nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't sign user ID: %v", err)
	}
	return &openpgp.Entity{
		PrimaryKey: pub,
		PrivateKey: priv,
		Identities: map[string]*openpgp.Identity{
			uid.Id: {
				Name:          uid.Name,
				UserId:        uid,
				SelfSignature: &selfSignature,
			},
		},
	}, nil
}

// synthesizeEntities returns an array of signing and decrypting Entities for
// k's cryptographic keys.
// Because OpenPGP entities must be self-signed, this function needs a physical
// touch on the yubikey for slots with touch policies that require it.
func (k *SecurityKey) synthesizeEntities(name, email string) ([]Entity,
	[]Entity, error) {
	now := time.Now()
	var signing, decrypting []Entity
	for _, sk := range k.SigningKeys() {
		e, err := k.synthesizeEntity(&sk.CryptoKey, now, name, email,
			fmt.Sprintf("piv-agent signing key; touch-policy %s",
				touchStringMap[sk.CryptoKey.SlotSpec.TouchPolicy]))
		if err != nil {
			return nil, nil, fmt.Errorf("couldn't synthesize entity: %v", err)
		}
		signing = append(signing, Entity{Entity: *e, CryptoKey: sk.CryptoKey})
	}
	for _, dk := range k.DecryptingKeys() {
		e, err := k.synthesizeEntity(&dk.CryptoKey, now, name, email,
			fmt.Sprintf("piv-agent decrypting key; touch-policy %s",
				touchStringMap[dk.CryptoKey.SlotSpec.TouchPolicy]))
		if err != nil {
			return nil, nil, fmt.Errorf("couldn't synthesize entity: %v", err)
		}
		decrypting = append(decrypting, Entity{Entity: *e, CryptoKey: dk.CryptoKey})
	}
	return signing, decrypting, nil
}

func (k *SecurityKey) armorEntity(e *openpgp.Entity,
	t piv.TouchPolicy) (string, error) {
	buf := bytes.Buffer{}
	w, err := armor.Encode(&buf, openpgp.PublicKeyType,
		map[string]string{
			"Comment": fmt.Sprintf("%v #%v, touch policy: %s",
				k.card, k.serial, touchStringMap[t]),
		})
	if err != nil {
		return "", fmt.Errorf("couldn't get PGP public key armorer: %w", err)
	}
	err = e.Serialize(w)
	if err != nil {
		return "", fmt.Errorf("couldn't serialize PGP public key: %w", err)
	}
	err = w.Close()
	if err != nil {
		return "", fmt.Errorf("couldn't close pgp writer: %w", err)
	}
	return buf.String(), nil
}

// StringsGPG returns an array of commonly formatted GPG keys as strings.
func (k *SecurityKey) StringsGPG(name, email string) ([]string, error) {
	var ss []string
	signing, decrypting, err := k.synthesizeEntities(name, email)
	if err != nil {
		return nil, fmt.Errorf("couldn't synthesize entities: %v", err)
	}
	ss = append(ss, "\nSigning GPG Keys:")
	for _, key := range signing {
		s, err := k.armorEntity(&key.Entity, key.SlotSpec.TouchPolicy)
		if err != nil {
			return nil, fmt.Errorf("couldn't armor entity: %v", err)
		}
		ss = append(ss, s)
	}
	ss = append(ss, "\nDecrypting GPG Keys:")
	for _, key := range decrypting {
		s, err := k.armorEntity(&key.Entity, key.SlotSpec.TouchPolicy)
		if err != nil {
			return nil, fmt.Errorf("couldn't armor entity: %v", err)
		}
		ss = append(ss, s)
	}
	return ss, nil
}
