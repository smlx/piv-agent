package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/smlx/piv-agent/internal/pivagent"
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
func (cmd *ListCmd) Run(p *pivagent.PIVAgent) error {
	secKeys, err := p.SecurityKeys()
	if err != nil {
		return fmt.Errorf("couldn't get security keys: %w", err)
	}
	fmt.Println("security keys (cards):")
	for _, k := range secKeys {
		fmt.Println(k.Card)
	}
	fmt.Println("ssh keys:")
	for _, k := range secKeys {
		for _, s := range k.SigningKeys {
			fmt.Printf("%s %s\n",
				strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(s.PubSSH)), "\n"),
				fmt.Sprintf("%v #%v, touch policy: %s", k.Card, k.Serial,
					touchStringMap[s.TouchPolicy]))
		}
		fmt.Println("\npgp keys:")
		buf := bytes.Buffer{}
		for _, s := range k.SigningKeys {
			buf.Reset()
			w, err := armor.Encode(&buf, openpgp.PublicKeyType,
				map[string]string{
					"Comment": fmt.Sprintf("%v #%v, touch policy: %s", k.Card, k.Serial, touchStringMap[s.TouchPolicy]),
				})
			if err != nil {
				return fmt.Errorf("couldn't set up PGP public key armor encoder: %w", err)
			}
			err = s.PubPGP.Serialize(w)
			if err != nil {
				return fmt.Errorf("couldn't serialize PGP public key: %w", err)
			}
			err = w.Close()
			if err != nil {
				return fmt.Errorf("couldn't close pgp writer: %w", err)
			}
			fmt.Println(buf.String())
		}
	}
	return nil
}
