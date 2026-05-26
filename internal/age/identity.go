package age

import (
	"encoding/binary"
	"fmt"

	"filippo.io/age/plugin"
)

const (
	identityVersion = 1
	identityLength  = 18
)

// Identity represents the data bound to a hardware security key slot.
type Identity struct {
	// Version represents the age-plugin-piv-agent identity version. Currently
	// only 1 is supported.
	Version uint8
	// Serial represents the serial of the yubikey associated with this identity.
	Serial uint32
	// Slot represents the slot on the yubikey associated with this identity.
	Slot byte
	// KeyTag is the truncated SHA256 hash of the public key in the given slot.
	KeyTag [4]byte
	// SeedFileID is the truncated SHA256 hash of the ML-KEM encapsulation key
	// concatenated with the slot's key tag.
	SeedFileID [8]byte
}

// NewIdentity creates a new Identity struct.
func NewIdentity(
	serial uint32,
	slot byte,
	keyTag [4]byte,
	fileID [8]byte,
) *Identity {
	return &Identity{
		Version:    identityVersion,
		Serial:     serial,
		Slot:       slot,
		KeyTag:     keyTag,
		SeedFileID: fileID,
	}
}

// Encode converts the Identity into the standard age plugin format.
func (i *Identity) Encode() (string, error) {
	data, err := i.MarshalBinary()
	if err != nil {
		return "", err
	}
	// encode identity to the standard age plugin format
	return plugin.EncodeIdentity("piv-agent", data), nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (i *Identity) MarshalBinary() ([]byte, error) {
	// construct the identity data structure (18 bytes)
	// - Version    (1 byte)
	// - Serial     (4 bytes)
	// - Slot       (1 byte)
	// - KeyTag     (4 bytes)
	// - SeedFileID (8 bytes)
	data := make([]byte, identityLength)
	data[0] = i.Version
	binary.BigEndian.PutUint32(data[1:5], i.Serial)
	data[5] = i.Slot
	copy(data[6:10], i.KeyTag[:])
	copy(data[10:18], i.SeedFileID[:])
	return data, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (i *Identity) UnmarshalBinary(data []byte) error {
	// validate identity data length
	if len(data) != identityLength {
		return fmt.Errorf("invalid identity data length: %d", len(data))
	}
	// parse and validate version
	version := data[0]
	if version != identityVersion {
		return fmt.Errorf("unsupported identity version: %d", version)
	}
	// extract version, serial, slotID, keyTag, fileID
	i.Version = version
	i.Serial = binary.BigEndian.Uint32(data[1:5])
	i.Slot = data[5]
	copy(i.KeyTag[:], data[6:10])
	copy(i.SeedFileID[:], data[10:18])
	return nil
}
