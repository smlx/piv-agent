package securitykey

import "fmt"

// SetupSlots configures slots on the security key without resetting it
// completely.
func (k *SecurityKey) SetupSlots(pin, version string, reset bool,
	signingKeys []string, decryptingKey bool) error {
	var err error
	if !reset {
		setUp, err := k.checkSlotsSetUp(signingKeys, decryptingKey)
		if err != nil {
			return fmt.Errorf("couldn't check slots: %v", err)
		}
		if setUp {
			return ErrKeySetUp
		}
	}
	// get the management key
	metadata, err := k.yubikey.Metadata(pin)
	if err != nil {
		return fmt.Errorf("coudnt' get metadata: %v", err)
	}
	// setup signing keys
	for _, p := range signingKeys {
		err := k.configureSlot(*metadata.ManagementKey, defaultSignSlots[p],
			version)
		if err != nil {
			return fmt.Errorf("couldn't configure slot %v: %v", defaultSignSlots[p],
				err)
		}
	}
	// setup decrypt key
	if decryptingKey {
		err := k.configureSlot(*metadata.ManagementKey,
			defaultDecryptSlots["never"], version)
		if err != nil {
			return fmt.Errorf("couldn't configure slot %v: %v",
				defaultDecryptSlots["cached"], err)
		}
	}
	return nil
}
