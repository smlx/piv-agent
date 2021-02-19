package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/smlx/piv-agent/internal/token"
	"go.uber.org/zap"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/ssh"
)

// ListCmd represents the list command.
type ListCmd struct{}

var touchStringMap = map[piv.TouchPolicy]string{
	piv.TouchPolicyNever:  "never",
	piv.TouchPolicyAlways: "always",
	piv.TouchPolicyCached: "cached",
}

// Run the list command.
func (cmd *ListCmd) Run(log *zap.Logger) error {
	tokens, err := token.List(log)
	if err != nil {
		return fmt.Errorf("couldn't get security keys: %w", err)
	}
	fmt.Println("security keys (cards):")
	for _, t := range tokens {
		fmt.Println(t.Card)
	}
	signingKeys, err := token.SigningKeys(tokens)
	if err != nil {
		return fmt.Errorf("couldn't get SSH public keys: %w", err)
	}
	fmt.Println("ssh keys:")
	for _, k := range signingKeys {
		fmt.Printf("%s %s\n",
			strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(k.PubSSH)), "\n"),
			fmt.Sprintf("%v #%v, touch policy: %s", k.Card, k.Serial,
				touchStringMap[k.TouchPolicy]))
	}
	fmt.Println("\npgp keys:")
	buf := bytes.Buffer{}
	for _, k := range signingKeys {
		buf.Reset()
		w, err := armor.Encode(&buf, openpgp.PublicKeyType,
			map[string]string{
				"Comment": fmt.Sprintf("%v #%v, touch policy: %s", k.Card, k.Serial, touchStringMap[k.TouchPolicy]),
			})
		if err != nil {
			return fmt.Errorf("couldn't set up PGP public key armor encoder: %w", err)
		}
		err = k.PubPGP.Serialize(w)
		if err != nil {
			return fmt.Errorf("couldn't serialize PGP public key: %w", err)
		}
		err = w.Close()
		if err != nil {
			return fmt.Errorf("couldn't close pgp writer: %w", err)
		}
		fmt.Println(buf.String())
	}
	return nil
}
