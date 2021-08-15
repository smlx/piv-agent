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
	SigningKey
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
			k.Comment(s.SlotSpec)))
	}
	return ss
}

// synthesizeEntities returns an array of Entities for on k's signing keys.
// Because entities must be self-signed, this function needs a physical touch
// on the yubikey for slots with touch policies that require it.
func (k *SecurityKey) synthesizeEntities(name, email string) ([]Entity, error) {
	now := time.Now()
	var entities []Entity
	for _, signingKey := range k.SigningKeys() {
		cryptoPrivKey, err := k.PrivateKey(&signingKey)
		if err != nil {
			return nil, fmt.Errorf("couldn't get private key: %v", err)
		}
		signer, ok := cryptoPrivKey.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("private key is invalid type")
		}
		comment := fmt.Sprintf("piv-agent synthesized; touch-policy %s",
			touchStringMap[signingKey.SlotSpec.TouchPolicy])
		uid := packet.NewUserId(name, comment, email)
		if uid == nil {
			return nil, errors.InvalidArgumentError("invalid characters in user ID")
		}
		ecdsaPubKey, ok := signingKey.Public.(*ecdsa.PublicKey)
		if !ok {
			// TODO: handle ed25519 keys
			fmt.Println("skipping non-ECDSA public key")
			continue
		}
		pub := packet.NewECDSAPublicKey(now, ecdsaPubKey)
		priv := packet.NewSignerPrivateKey(now, signer)
		selfSignature := packet.Signature{
			CreationTime: now,
			SigType:      packet.SigTypePositiveCert,
			// TODO: determine the key type
			// TODO: support ECDH
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
		e := openpgp.Entity{
			PrimaryKey: pub,
			PrivateKey: priv,
			Identities: map[string]*openpgp.Identity{
				uid.Id: {
					Name:          uid.Name,
					UserId:        uid,
					SelfSignature: &selfSignature,
				},
			},
		}
		entities = append(entities, Entity{Entity: e, SigningKey: signingKey})
	}
	return entities, nil
}

// StringsGPG returns an array of commonly formatted GPG keys as strings.
func (k *SecurityKey) StringsGPG(name, email string) ([]string, error) {
	var ss []string
	buf := bytes.Buffer{}
	entities, err := k.synthesizeEntities(name, email)
	if err != nil {
		return nil, fmt.Errorf("couldn't synthesize entities: %v", err)
	}
	for _, e := range entities {
		buf.Reset()
		w, err := armor.Encode(&buf, openpgp.PublicKeyType,
			map[string]string{
				"Comment": fmt.Sprintf("%v #%v, touch policy: %s",
					k.card, k.serial, touchStringMap[e.SlotSpec.TouchPolicy]),
			})
		if err != nil {
			return nil, fmt.Errorf("couldn't get PGP public key armorer: %w", err)
		}
		err = e.Serialize(w)
		if err != nil {
			return nil, fmt.Errorf("couldn't serialize PGP public key: %w", err)
		}
		err = w.Close()
		if err != nil {
			return nil, fmt.Errorf("couldn't close pgp writer: %w", err)
		}
		ss = append(ss, buf.String())
	}
	return ss, nil
}
