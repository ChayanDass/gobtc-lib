package address

import (
	"errors"
	"fmt"

	networks "github.com/ChayanDass/gobtc-lib/Network"
	utils "github.com/ChayanDass/gobtc-lib/utils"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	PayToPublicKeyHash        = "pubkeyhash"
	PayToScriptHash           = "scripthash"
	PayToWitnessPublicKeyHash = "witnesspubkeyhash"
	PayToWitnessScriptHash    = "witnessscripthash"
	PayToTaproot              = "taproot"
)

// Address represents a Bitcoin address
type Address struct {
	Data     *secp.PublicKey
	Network  *networks.Network
	Type     string
	MultiSig string
}

// Returns the Bitcoin address as string
func (a *Address) ToString() string {
	if a.Data == nil {
		return ""
	}
	pub := a.Data.SerializeCompressed()
	hash160 := utils.Hash160(pub)
	version := []byte{a.Network.PubKeyHash}
	payload := append(version, hash160...)
	checksum := utils.DoubleSHA256(payload)[:4]
	full := append(payload, checksum...)
	return utils.Encode(full)
}

// NewAddress constructs a new Address instance
func NewAddress(opts *Address) (string, error) {
	if opts == nil {
		return "", errors.New("options cannot be nil")
	}
	// Validate Type
	addrType := opts.Type
	if addrType != "" &&
		addrType != PayToPublicKeyHash &&
		addrType != PayToScriptHash &&
		addrType != PayToWitnessPublicKeyHash &&
		addrType != PayToWitnessScriptHash &&
		addrType != PayToTaproot {
		return "", fmt.Errorf("invalid type: %s; must be 'pubkeyhash', 'scripthash', 'witnesspubkeyhash', 'witnessscripthash', or 'taproot'", addrType)
	}
	return opts.ToString(), nil

}
