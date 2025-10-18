package Address

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
	Address  string
	Network  *networks.Network
	Type     string
	MultiSig string
}
type KeyOptions struct {
	Data     *secp.PublicKey
	Network  *networks.Network
	Type     string
	MultiSig string
}

// Returns the Bitcoin address as string
func (a *Address) ToString() string {
	return a.Address

}

// NewAddress constructs a new Address instance
func NewAddress(opts *KeyOptions) (*Address, error) {
	if opts == nil {
		return nil, errors.New("options cannot be nil")
	}
	// Validate Type
	addrType := opts.Type
	if addrType != "" &&
		addrType != PayToPublicKeyHash &&
		addrType != PayToScriptHash &&
		addrType != PayToWitnessPublicKeyHash &&
		addrType != PayToWitnessScriptHash &&
		addrType != PayToTaproot {
		return nil, fmt.Errorf("invalid type: %s; must be 'pubkeyhash', 'scripthash', 'witnesspubkeyhash', 'witnessscripthash', or 'taproot'", addrType)
	}
	return TransformPublicKey(opts)

}

// transformPublicKey takes KeyOptions and returns the encoded address string
// TransformPublicKey converts a given public key into a Bitcoin address
func TransformPublicKey(opts *KeyOptions) (*Address, error) {
	if opts == nil {
		return nil, errors.New("options cannot be nil")
	}
	if opts.Data == nil {
		return nil, errors.New("public key cannot be nil")
	}

	// Default to P2PKH if type is empty
	addrType := opts.Type
	if addrType == "" {
		addrType = PayToPublicKeyHash
	}

	// Default to mainnet if network not specified
	net := opts.Network
	if net == nil {
		net = networks.Default
	}

	pubKey := opts.Data.SerializeCompressed()
	var address string

	switch addrType {
	case PayToPublicKeyHash:
		// Legacy P2PKH
		hash160 := utils.Hash160(pubKey)
		version := []byte{net.PubKeyHash}
		payload := append(version, hash160...)
		checksum := utils.DoubleSHA256(payload)[:4]
		full := append(payload, checksum...)
		address = utils.Encode(full)

	case PayToScriptHash:
		return nil, errors.New("P2SH transformation not implemented yet")

	// Uncomment when utils has Bech32 functions
	// case PayToWitnessPublicKeyHash:
	// 	hash160 := utils.Hash160(pubKey)
	// 	address = utils.Bech32Encode(net.Bech32Prefix, hash160)

	// case PayToTaproot:
	// 	taprootHash := utils.SHA256(pubKey)
	// 	address = utils.Bech32mEncode(net.Bech32Prefix, taprootHash)

	default:
		return nil, fmt.Errorf("unsupported address type: %s", addrType)
	}

	return &Address{
		Address:  address,
		Network:  net,
		Type:     addrType,
		MultiSig: opts.MultiSig,
	}, nil
}
