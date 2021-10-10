package assuan

import "bytes"

// Work around bug(?) in gnupg where some byte sequences are
// percent-encoded in the sexp. Yes, really. NFI what to do if the
// percent-encoded byte sequences themselves are part of the
// ciphertext. Yikes.
//
// These two functions represent over a week of late nights stepping through
// debug builds of libcrypt in gdb :-(

// PercentDecodeSExp replaces the percent-encoded byte sequences with their raw
// byte values.
func PercentDecodeSExp(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte{0x25, 0x32, 0x35}, []byte{0x25}) // %
	data = bytes.ReplaceAll(data, []byte{0x25, 0x30, 0x41}, []byte{0x0a}) // \n
	data = bytes.ReplaceAll(data, []byte{0x25, 0x30, 0x44}, []byte{0x0d}) // \r
	return data
}

// PercentEncodeSExp replaces the raw byte values with their percent-encoded
// byte sequences.
func PercentEncodeSExp(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte{0x25}, []byte{0x25, 0x32, 0x35})
	data = bytes.ReplaceAll(data, []byte{0x0a}, []byte{0x25, 0x30, 0x41})
	data = bytes.ReplaceAll(data, []byte{0x0d}, []byte{0x25, 0x30, 0x44})
	return data
}
