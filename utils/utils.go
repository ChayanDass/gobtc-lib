package base58

import (
	"crypto/sha256"

	"golang.org/x/crypto/ripemd160"
)

// Utility: DoubleSHA256
func DoubleSHA256(b []byte) []byte {
	h1 := SHA256(b)
	h2 := SHA256(h1)
	return h2
}

// Utility: SHA256
func SHA256(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// Utility: Hash160 = RIPEMD160(SHA256(data))
func Hash160(b []byte) []byte {
	sha := SHA256(b)
	rip := Ripemd160(sha)
	return rip
}

// Ripemd160 implementation (you can use crypto/ripemd160 if not deprecated)
func Ripemd160(data []byte) []byte {
	h := ripemd160.New()
	h.Write(data)
	return h.Sum(nil)
}
