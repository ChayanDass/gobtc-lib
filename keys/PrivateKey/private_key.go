package privatekey

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	networks "github.com/ChayanDass/gobtc-lib/Network"
	base58 "github.com/ChayanDass/gobtc-lib/utils"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

type PrivateKey struct {
	Key        *secp.PrivateKey
	Compressed bool
	Network    *networks.Network
}

// NewPrivateKey creates a new private key for the given network.
// Accepts either a string (network name) or a *Network object.
func NewPrivateKey(netArg interface{}) (*PrivateKey, error) {
	var net *networks.Network
	var err error
	switch v := netArg.(type) {
	case string:
		// If it's a string, try to get the network by name
		net, err = networks.Get(v)
		if err != nil {
			return nil, fmt.Errorf("unknown network: %v", v)
		}
	case *networks.Network:
		// If it's already a network object, use it
		net = v
	case nil:
		// Default network (mainnet)
		net = networks.Default
	default:
		return nil, errors.New("invalid type for netArg: must be string or *Network")
	}
	priv, err := secp.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		Key:        priv,
		Compressed: true,
		Network:    net,
	}, nil
}
func (pk *PrivateKey) ToString() string {
	if pk == nil || pk.Key == nil {
		return "<nil>"
	}
	return hex.EncodeToString(pk.Key.Serialize())
}

// ToAddress (Legacy P2PKH)
func (p *PrivateKey) ToAddress() (string, error) {
	pub := p.ToPublicKey().SerializeCompressed()
	hash160 := Hash160(pub)
	version := []byte{p.Network.PubKeyHash}
	payload := append(version, hash160...)
	checksum := DoubleSHA256(payload)[:4]
	full := append(payload, checksum...)
	return base58.Encode(full), nil
}

// ToWIF converts the private key to Wallet Import Format
func (p *PrivateKey) ToWIF() string {
	prefix := []byte{p.Network.PrivateKey}
	keyBytes := p.Key.Serialize()

	var buf []byte
	if p.Compressed {
		buf = append(prefix, append(keyBytes, 0x01)...)
	} else {
		buf = append(prefix, keyBytes...)
	}

	checksum := DoubleSHA256(buf)[:4]
	final := append(buf, checksum...)
	return base58.Encode(final)
}

// ToHex returns the private key in hex form
func (p *PrivateKey) ToHex() string {
	return hex.EncodeToString(p.Key.Serialize())
}

// PublicKey derives the corresponding public key
func (p *PrivateKey) ToPublicKey() *secp.PublicKey {
	return p.Key.PubKey()
}

// FromHex creates a PrivateKey from hex string
func FromHex(hexKey string, netName string) (*PrivateKey, error) {
	bytesKey, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	return FromBytes(bytesKey, netName)
}

// FromBytes creates PrivateKey from 32-byte buffer
func FromBytes(b []byte, netName string) (*PrivateKey, error) {
	if len(b) != 32 {
		return nil, errors.New("private key must be 32 bytes")
	}
	net, err := networks.Get(netName)
	if err != nil {
		return nil, err
	}

	priv := secp.PrivKeyFromBytes(b)
	return &PrivateKey{Key: priv, Compressed: true, Network: net}, nil
}

// FromWIF decodes a WIF-encoded private key
func FromWIF(wif string) (*PrivateKey, error) {
	data := base58.Decode(wif)
	if len(data) < 33 {
		return nil, errors.New("invalid WIF length")
	}

	checksum := data[len(data)-4:]
	payload := data[:len(data)-4]

	// Verify Base58Check
	hash := DoubleSHA256(payload)
	if !bytes.Equal(hash[:4], checksum) {
		return nil, errors.New("invalid WIF checksum")
	}

	prefix := payload[0]
	var net *networks.Network
	if n, err := networks.Get(prefix); err == nil {
		net = n
	}

	compressed := false
	keyBytes := payload[1:]
	if len(keyBytes) == 33 && keyBytes[32] == 0x01 {
		keyBytes = keyBytes[:32]
		compressed = true
	}

	priv := secp.PrivKeyFromBytes(keyBytes)
	return &PrivateKey{Key: priv, Compressed: compressed, Network: net}, nil
}

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
