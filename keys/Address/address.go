package Address

import (
	"encoding/hex"
	"errors"
	"fmt"

	networks "github.com/ChayanDass/gobtc-lib/Network"
	utils "github.com/ChayanDass/gobtc-lib/utils"
	"github.com/ChayanDass/gobtc-lib/utils/base58"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	PayToPublicKeyHash        = "pubkeyhash"
	PayToScriptHash           = "scripthash"
	PayToWitnessPublicKeyHash = "witnesspubkeyhash"
	PayToWitnessScriptHash    = "witnessscripthash"
	PayToTaproot              = "taproot"
)

// --- Helpers to detect address type ---
func (a *Address) IsPayToPublicKeyHash() bool        { return a.Type == PayToPublicKeyHash }
func (a *Address) IsPayToScriptHash() bool           { return a.Type == PayToScriptHash }
func (a *Address) IsPayToWitnessPublicKeyHash() bool { return a.Type == PayToWitnessPublicKeyHash }
func (a *Address) IsPayToWitnessScriptHash() bool    { return a.Type == PayToWitnessScriptHash }
func (a *Address) IsPayToTaproot() bool              { return a.Type == PayToTaproot }

// --- Get version byte for Base58Check ---
func (a *Address) NetworkByte() byte {
	switch a.Type {
	case PayToPublicKeyHash:
		return a.Network.PubKeyHash
	case PayToScriptHash:
		return a.Network.ScriptHash
	default:
		return 0x00
	}
}

// Address represents a Bitcoin address
type Address struct {
	Network    *networks.Network
	Type       string
	HashBuffer []byte // hash160(pubkey) or script hash
	MultiSig   string
}
type KeyOptions struct {
	Data     *secp.PublicKey
	Network  *networks.Network
	Type     string
	MultiSig string
}

// ToString returns Base58Check encoded address (legacy only)
func (a *Address) ToString() string {
	version := a.NetworkByte()
	return base58.CheckEncode(a.HashBuffer, version)
}

// HashHex return the PubHash at hex format
func (a *Address) HashHex() string {
	return hex.EncodeToString(a.HashBuffer)
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
	var hash160 []byte

	switch addrType {
	case PayToPublicKeyHash:
		// Legacy P2PKH
		hash160 = utils.Hash160(pubKey)
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
		Network:    net,
		Type:       addrType,
		MultiSig:   opts.MultiSig,
		HashBuffer: hash160,
	}, nil
}
func FromPublicKey(opts *KeyOptions) (*Address, error) {
	if opts == nil {
		return nil, errors.New("options cannot be nil")
	}

	// Use default network if nil or empty
	network := opts.Network
	if network == nil || network.Name == "" {
		network = networks.Default
	}

	// Transform public key to address info
	info, err := TransformPublicKey(opts)
	if err != nil {
		return nil, err
	}

	// Return fully initialized Address
	return &Address{
		HashBuffer: info.HashBuffer,
		Network:    network,
		Type:       info.Type,
		MultiSig:   opts.MultiSig,
	}, nil
}
