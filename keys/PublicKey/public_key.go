package keys

import (
	networks "github.com/ChayanDass/gobtc-lib/Network"
	privatekey "github.com/ChayanDass/gobtc-lib/keys/PrivateKey"

	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

type PublicKey struct {
	Point      *secp256k1.PublicKey
	Compressed bool
	Network    *networks.Network
}

// ------------------------------
// Constructors
// ------------------------------

// NewPublicKey creates a public key from different possible inputs (like JS classifyArgs)
func NewPublicKey(data interface{}, compressed bool, net interface{}) (*PublicKey, error) {
	var point *secp256k1.PublicKey
	var network *networks.Network
	var err error

	// Parse network
	switch v := net.(type) {
	case string:
		network, err = networks.Get(v)
		if err != nil {
			return nil, err
		}
	case *networks.Network:
		network = v
	default:
		network = networks.Mainnet
	}

	switch val := data.(type) {
	case *secp256k1.PublicKey:
		point = val
	case []byte:
		point, err = secp256k1.ParsePubKey(val)
		if err != nil {
			return nil, err
		}
	case string:
		b, err := hex.DecodeString(val)
		if err != nil {
			return nil, err
		}
		point, err = secp256k1.ParsePubKey(b)
		if err != nil {
			return nil, err
		}
	case *privatekey.PrivateKey:
		point = val.Key.PubKey()
		compressed = val.Compressed
		network = val.Network
	default:
		return nil, errors.New("unsupported public key input type")
	}

	return &PublicKey{
		Point:      point,
		Compressed: compressed,
		Network:    network,
	}, nil
}

// FromPrivateKey derives a public key from a private key
func FromPrivateKey(priv *privatekey.PrivateKey) *PublicKey {
	return &PublicKey{
		Point:      priv.Key.PubKey(),
		Compressed: priv.Compressed,
		Network:    priv.Network,
	}
}

// FromBytes parses a public key from DER or compressed bytes
// func FromBytes(buf []byte) (*PublicKey, error) {
// 	pk, err := secp256k1.ParsePubKey(buf)
// 	if err != nil {
// 		return nil, err
// 	}
// 	compressed := len(buf) == 33
// 	return &PublicKey{
// 		Point:      pk,
// 		Compressed: compressed,
// 		Network:    Network.Default(),
// 	}, nil
// }

// FromHex parses a public key from a hex string
// func FromHex(str string) (*PublicKey, error) {
// 	b, err := hex.DecodeString(str)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return FromBytes(b)
// }

// ------------------------------
// Serialization
// ------------------------------

// ToBytes serializes to DER/compressed format
func (p *PublicKey) ToBytes() []byte {
	if p.Compressed {
		return p.Point.SerializeCompressed()
	}
	return p.Point.SerializeUncompressed()
}

// ToHex returns DER hex string
func (p *PublicKey) ToHex() string {
	return hex.EncodeToString(p.ToBytes())
}

// String implements fmt.Stringer for readable print
func (p *PublicKey) String() string {
	return fmt.Sprintf("PublicKey[%s]", p.ToHex())
}

// ------------------------------
// Hashing
// ------------------------------

// Hash160 performs SHA256 + RIPEMD160
func (p *PublicKey) Hash160() []byte {
	h := sha256.Sum256(p.ToBytes())
	r := ripemd160.New()
	r.Write(h[:])
	return r.Sum(nil)
}

// ------------------------------
// Utility
// ------------------------------

// Equals compares two public keys
func (p *PublicKey) Equals(other *PublicKey) bool {
	if p == nil || other == nil {
		return false
	}
	return bytes.Equal(p.ToBytes(), other.ToBytes())
}

// Validate checks that public key is on the secp256k1 curve
func (p *PublicKey) Validate() error {
	if p.Point == nil {
		return errors.New("invalid public key: nil point")
	}
	if !p.Point.IsOnCurve() {
		return errors.New("invalid public key: not on secp256k1 curve")
	}
	return nil
}
