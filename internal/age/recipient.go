package age

import (
	"crypto/mlkem"
	"crypto/sha256"

	"filippo.io/age/plugin"
)

// EncodeRecipient combines the public ML-KEM and ECDH components and encodes
// them as an age plugin recipient string.
func EncodeRecipient(mlkemPub, ecdhPub []byte) string {
	var pub []byte
	pub = append(pub, mlkemPub...)
	pub = append(pub, ecdhPub...)
	return plugin.EncodeRecipient("piv-agent", pub)
}

// CalculateSeedFileID computes the 8-byte file ID that binds a seed to a specific
// slot. It is calculated as the truncated SHA-256 hash of the concatenated
// ML-KEM encapsulation key and the 4-byte P-256 keyTag.
func CalculateSeedFileID(dk *mlkem.DecapsulationKey768, keyTag [4]byte) []byte {
	hashInput := append(dk.EncapsulationKey().Bytes(), keyTag[:]...)
	hash := sha256.Sum256(hashInput)
	return hash[:8]
}
