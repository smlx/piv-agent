package gpg

import (
	"fmt"
	"io"
	"os"
	"path"

	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
)

// keyfilePrivateKeys reads the given path and returns any private keys found.
func keyfilePrivateKeys(p string) ([]*packet.PrivateKey, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("couldn't open path %s: %v", p, err)
	}
	fileInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("couldn't stat path %s: %v", p, err)

	}
	switch {
	case fileInfo.Mode().IsRegular():
		return keysFromFile(f)
	case fileInfo.IsDir():
		// enumerate files in directory
		dirents, err := f.ReadDir(0)
		if err != nil {
			return nil, fmt.Errorf("couldn't read directory")
		}
		// get any private keys from each file
		var privKeys []*packet.PrivateKey
		for _, dirent := range dirents {
			direntInfo, err := dirent.Info()
			if err != nil {
				return nil, fmt.Errorf("couldn't stat directory entry")
			}
			// ignore subdirectories
			if direntInfo.Mode().IsRegular() {
				subPath := path.Join(p, dirent.Name())
				ff, err := os.Open(subPath)
				if err != nil {
					return nil, fmt.Errorf("couldn't open path %s: %v", subPath, err)
				}
				subPrivKeys, err := keysFromFile(ff)
				if err != nil {
					return nil,
						fmt.Errorf("couldn't get keys from file %s: %v", subPath, err)
				}
				privKeys = append(privKeys, subPrivKeys...)
			}
		}
		return privKeys, nil
	default:
		return nil, fmt.Errorf("invalid file type for path to keyfiles")
	}
}

// keysFromFile read a file and return any private keys found
func keysFromFile(f *os.File) ([]*packet.PrivateKey, error) {
	var err error
	var pkt packet.Packet
	var privKeys []*packet.PrivateKey
	reader := packet.NewReader(f)
	for pkt, err = reader.Next(); err != io.EOF; pkt, err = reader.Next() {
		if _, ok := err.(errors.UnsupportedError); ok {
			continue // gpg writes some non-standard cruft
		}
		if err != nil {
			return nil, fmt.Errorf("couldn't get next packet: %v", err)
		}
		k, ok := pkt.(*packet.PrivateKey)
		if !ok {
			continue
		}
		privKeys = append(privKeys, k)
	}
	return privKeys, nil
}
