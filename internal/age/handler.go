package age

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/tag"
	"filippo.io/hpke"
	hpkecrypto "filippo.io/hpke/crypto"
	"golang.org/x/crypto/hkdf"

	"github.com/smlx/piv-agent/internal/notify"
)

const (
	// stanzaType is the expected type of the age recipient stanza.
	stanzaType = "mlkem768p256tag"
	// stanzaArgsCount is the expected number of arguments in the stanza.
	stanzaArgsCount = 2
	// tagLength is the expected length of the decoded tag.
	tagLength = 4
	// encapsulatedKeyLength is the expected length in bytes of the encapsulated
	// key.
	// 1088 (ML-KEM ciphertext) + 65 (uncompressed P-256).
	encapsulatedKeyLength = 1153
	// encryptedFileKeyLength is the expected length of the stanza body.
	encryptedFileKeyLength = 32
	// hpkeInfo is the info string used in the HPKE context.
	hpkeInfo = "age-encryption.org/mlkem768p256tag"
)

// ECDHKey represents a key that can perform ECDH key exchange.
type ECDHKey interface {
	Public() crypto.PublicKey
	ECDH(peer *ecdh.PublicKey) ([]byte, error)
}

// ECDHService provides a method to retrieve an ECDHKey.
type ECDHService interface {
	GetECDHKey(
		serial,
		slotID uint32,
		keyTag [4]byte,
	) (ECDHKey, error)
}

// SeedFetcher defines a function signature for retrieving ML-KEM seeds.
// The fileID identifies the seed on disk and is calculated by hashing the
// concatenation of the ML-KEM encapsulation key (the public part of the seed,
// which can be generated from the private seed bytes) and the 4-byte P-256
// keyTag (defined in the age standard as "the truncated SHA-256 hash of the
// uncompressed P-256 point encoding only").
//
// Depending on both components for the fileID:
//
//  1. Allows multiple YubiKeys to be used with a single laptop: the fileID
//     binds the seed to a specific P-256 keyTag, and therefore to a specific
//     slot on a specific YubiKey. This allows the agent to scan a directory of
//     seeds and correctly identify which seed belongs to which connected
//     YubiKey and slot.
//  2. Enables efficient seed discovery and stanza filtering: because the
//     fileID is derived purely from public key material, the agent can scan
//     seeds, associate them with hardware slots, and verify incoming age
//     stanzas without needing to perform slow private-key operations on the
//     YubiKey until a matching stanza is found.
//  3. Ensures the filename (fileID) is safe to share or store publicly. The
//     age identity string contains this fileID, allowing the agent to
//     instantly know the filename of the required seed on the hard drive
//     without decrypting seeds first. Once located, the seed file can be read
//     (unsealed by the systemd/TPM machinery) to obtain the private seed.
//  4. Enables the `age-plugin-piv-agent generate-seeds` command to warn if a
//     seed already exists for a given YubiKey + slot.
type SeedFetcher func(fileID [8]byte) ([]byte, error)

// pivKeyExchanger wraps ECDHKey to implement ecdh.KeyExchanger.
type pivKeyExchanger struct {
	key ECDHKey
}

// PublicKey returns the ECDH public key associated with the private key.
func (e *pivKeyExchanger) PublicKey() *ecdh.PublicKey {
	pub := e.key.Public().(*ecdsa.PublicKey)
	ep, err := pub.ECDH()
	if err != nil {
		panic(err)
	}
	return ep
}

// Curve returns the elliptic curve used for the key exchange.
func (e *pivKeyExchanger) Curve() ecdh.Curve {
	return ecdh.P256()
}

// ECDH performs an ECDH key exchange with the given peer public key.
func (e *pivKeyExchanger) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	return e.key.ECDH(peer)
}

// ageIdentity implements age.Identity for a hybrid P-256 + ML-KEM-768 key
// backed by a PIV token.
type ageIdentity struct {
	ident     Identity
	fetchSeed SeedFetcher
	piv       ECDHService
	notify    *notify.Notify
}

// Unwrap attempts to decrypt the file key from the provided age stanzas.
// It iterates over the stanzas and tries to unwrap the one that matches the
// expected type and tag.
//
// This function computes the expected tag using the encapsulated key and
// keyTag. It manually performs this calculation rather than using
// Recipient.Tag(), because instantiating a new tag.Recipient requires the full
// P-256 public key, which would force the agent to interact with the YubiKey
// just to check if the stanza is addressed to us. This is slow.
//
// The age specification calculates the tag using only a 4-byte truncated
// hash of the P-256 key, and this was parsed out of the identity string. So
// use that value to enable fast verification, and defer hardware access until
// a match is actually found.
func (i *ageIdentity) Unwrap(ss []*age.Stanza) ([]byte, error) {
	// Iterate over all stanzas to find a matching one that can be unwrapped.
	for _, s := range ss {
		// Ignore stanzas that are not of the expected type.
		if s.Type != stanzaType {
			continue
		}
		// Validate the number of arguments in the stanza.
		if len(s.Args) != stanzaArgsCount {
			return nil, fmt.Errorf("invalid stanza")
		}
		// Decode the tag argument from the stanza.
		tagArg, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[0])
		if err != nil {
			return nil, fmt.Errorf("invalid tag: %v", err)
		}
		// Validate the length of the decoded tag.
		if len(tagArg) != tagLength {
			return nil, fmt.Errorf("invalid tag length: %d", len(tagArg))
		}
		// Decode the encapsulated key from the stanza.
		enc, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[1])
		if err != nil {
			return nil, fmt.Errorf("invalid encapsulated key: %v", err)
		}
		// Validate the length of the encapsulated key.
		if len(enc) != encapsulatedKeyLength {
			return nil, fmt.Errorf("invalid encapsulated key length: %d", len(enc))
		}
		// Validate the length of the encrypted file key (stanza body).
		if len(s.Body) != encryptedFileKeyLength {
			return nil, fmt.Errorf("invalid encrypted file key length: %d", len(s.Body))
		}
		// 'ikm' is the Initial Keying Material. The age specification dictates
		// that the tag for the mlkem768p256tag recipient is calculated via
		// HKDF-SHA256, where the IKM is the concatenation of the encapsulated key
		// (enc) and the truncated 4-byte P-256 public key hash (AKA KeyTag).
		var ikm []byte
		ikm = append(ikm, enc...)
		ikm = append(ikm, i.ident.KeyTag[:]...)
		// The HKDF algorithm (RFC 5869) has two phases: Extract (which generates a
		// fixed-length pseudorandom key) and Expand (which expands it to arbitrary
		// length). hkdf.New() automatically performs *both* phases. However, the
		// age format specification explicitly defines the tag as:
		//
		//   tag = HKDF-Extract-SHA-256(ikm = ..., salt = ...)[:4]
		//
		// It strictly requires ONLY the Extract phase, taking the first 4 bytes of
		// the resulting PRK. Using hkdf.New() would improperly push the PRK
		// through the Expand phase, so use hkdf.Extract instead of hkdf.New.
		expTag := hkdf.Extract(sha256.New, ikm, []byte(hpkeInfo))[:tagLength]
		// Compare the provided tag with the expected tag. Continue if they don't
		// match.
		if !bytes.Equal(tagArg, expTag) {
			continue
		}
		// The tag matched, so this stanza is addressed to this identity. Get the
		// ECDH key from the hardware to decrypt it. This is the point at which
		// hardware is being accessed.
		ecdhKey, err := i.piv.GetECDHKey(
			i.ident.Serial, uint32(i.ident.Slot), i.ident.KeyTag)
		if err != nil {
			return nil, fmt.Errorf("couldn't get ECDH key from device: %v: %w", err, age.ErrIncorrectIdentity)
		}
		// Retrieve 64-byte seed for ML-KEM decapsulation key using the
		// content-addressable fileID.
		seed, err := i.fetchSeed(i.ident.SeedFileID)
		if err != nil {
			return nil, fmt.Errorf("couldn't fetch ML-KEM seed: %v: %w", err, age.ErrIncorrectIdentity)
		}
		// Construct the ML-KEM decapsulation key from the seed.
		mlkemKey, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			return nil, fmt.Errorf("couldn't derive MLKEM key: %v: %w", err, age.ErrIncorrectIdentity)
		}
		// Combine the ML-KEM key and the ECDH key into a single hybrid private key
		// for age decryption.
		k, err := hpke.NewHybridPrivateKey(
			hpkecrypto.DecapsulatorFromDecapsulationKey768(mlkemKey),
			&pivKeyExchanger{key: ecdhKey})
		if err != nil {
			return nil, fmt.Errorf("couldn't create hybrid private key: %v: %w", err, age.ErrIncorrectIdentity)
		}
		// Trigger touch notification before hardware decryption
		cancel := i.notify.Touch()
		defer cancel()
		// Construct the HPKE recipient context using the encapsulated key and
		// private key.
		r, err := hpke.NewRecipient(
			enc, k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(hpkeInfo))
		if err != nil {
			return nil, fmt.Errorf("couldn't construct recipient: %v: %w", err, age.ErrIncorrectIdentity)
		}
		// Decrypt the file key.
		fileKey, err := r.Open(nil, s.Body)
		if err == nil {
			return fileKey, nil
		}
		// Decryption failed. Since multiple identities can share the same YubiKey
		// (and therefore the same KeyTag), this stanza might simply be for another
		// identity. Continue trying other stanzas.
	}
	// Return an error if no stanza could be unwrapped.
	return nil, age.ErrIncorrectIdentity
}

// HandleRecipient returns an age plugin recipient handler.
// The handler creates a new recipient that encrypts file keys.
func HandleRecipient() func(data []byte) (age.Recipient, error) {
	return func(data []byte) (age.Recipient, error) {
		return tag.NewHybridRecipient(data)
	}
}

// HandleIdentity returns an age plugin identity handler.
//
// The handler returns an identity that can decrypt file keys using a PIV
// device (Yubikey) and an ML-KEM seed. The identity data contains routing
// information needed to locate the hardware token and corresponding ML-KEM
// seed.
func HandleIdentity(
	piv ECDHService,
	fetchSeed SeedFetcher,
	n *notify.Notify,
) func(data []byte) (age.Identity, error) {
	return func(data []byte) (age.Identity, error) {
		var ident Identity
		if err := ident.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		// Return the successfully constructed identity. Hardware token access
		// and seed fetching is deferred until a matching stanza is found during
		// Unwrap.
		return &ageIdentity{
			ident:     ident,
			fetchSeed: fetchSeed,
			piv:       piv,
			notify:    n,
		}, nil
	}
}
