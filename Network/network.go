package networks

import (
	"encoding/binary"
	"fmt"
)

// Network represents a Bitcoin network configuration
type Network struct {
	Name         string
	Alias        string
	PubKeyHash   byte
	ScriptHash   byte
	PrivateKey   byte
	Bech32Prefix string
	XPubKey      uint32
	XPrivKey     uint32
	NetworkMagic [4]byte
	Port         int
	DNSServers   []string
}

// Registry of all networks
var (
	networksList []*Network
	networkMap   = make(map[interface{}][]*Network)
)

// AddNetwork registers a new network configuration
func AddNetwork(data *Network) *Network {
	networksList = append(networksList, data)

	// Register in lookup map
	values := []interface{}{
		data.Name,
		data.Alias,
		data.PubKeyHash,
		data.ScriptHash,
		data.PrivateKey,
		data.Bech32Prefix,
		data.XPubKey,
		data.XPrivKey,
	}
	for _, v := range values {
		if v != nil {
			networkMap[v] = append(networkMap[v], data)
		}
	}
	return data
}

// Get retrieves a network by name, alias, or any key like pubkeyhash or prefix.
func Get(arg interface{}) (*Network, error) {
	if arr, ok := networkMap[arg]; ok && len(arr) > 0 {
		return arr[0], nil
	}
	return nil, fmt.Errorf("network not found: %v", arg)
}

// Is returns true if the string matches the network name or alias
func (n *Network) Is(name string) bool {
	return n.Name == name || n.Alias == name
}

// IntegerToMagic converts a 32-bit int to 4-byte magic buffer
func IntegerToMagic(i uint32) [4]byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], i)
	return buf
}

// remove network
func RemoveNetwork(data *Network) {
	// Remove from networksList
	for i, net := range networksList {
		if net == data {
			networksList = append(networksList[:i], networksList[i+1:]...)
			break
		}
	}

	// Remove from networkMap
	values := []interface{}{
		data.Name,
		data.Alias,
		data.PubKeyHash,
		data.ScriptHash,
		data.PrivateKey,
		data.Bech32Prefix,
		data.XPubKey,
		data.XPrivKey,
	}
	for _, v := range values {
		if v != nil {
			if arr, ok := networkMap[v]; ok {
				for i, net := range arr {
					if net == data {
						networkMap[v] = append(arr[:i], arr[i+1:]...)
						break
					}
				}
				if len(networkMap[v]) == 0 {
					delete(networkMap, v)
				}
			}

		}
	}
}

// Default networks
var (
	Mainnet = AddNetwork(&Network{
		Name:         "mainnet",
		Alias:        "livenet",
		PubKeyHash:   0x00,
		ScriptHash:   0x05,
		PrivateKey:   0x80,
		Bech32Prefix: "bc",
		XPubKey:      0x0488B21E,
		XPrivKey:     0x0488ADE4,
		NetworkMagic: IntegerToMagic(0xD9B4BEF9),
		Port:         8333,
		DNSServers: []string{
			"seed.bitcoin.sipa.be",
			"dnsseed.bluematt.me",
			"seed.bitcoinstats.com",
			"seed.bitnodes.io",
		},
	})

	Testnet = AddNetwork(&Network{
		Name:         "testnet",
		Alias:        "test",
		PubKeyHash:   0x6F,
		ScriptHash:   0xC4,
		PrivateKey:   0xEF,
		Bech32Prefix: "tb",
		XPubKey:      0x043587CF,
		XPrivKey:     0x04358394,
		NetworkMagic: IntegerToMagic(0x0709110B),
		Port:         18333,
		DNSServers: []string{
			"testnet-seed.bitcoin.jonasschnelli.ch",
			"seed.tbtc.petertodd.org",
			"testnet-seed.bluematt.me",
			"testnet-seed.bitcoin.schildbach.de",
		},
	})
	Default = Mainnet
)
