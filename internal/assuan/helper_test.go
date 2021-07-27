package assuan

import "crypto"

// KeyfileSigner wraps keyfileSigner() for testing purposes.
func KeyfileSigner(g GPGService, keygrip []byte) (crypto.Signer, error) {
	return keyfileSigner(g, keygrip)
}
