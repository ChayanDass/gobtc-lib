package main

import (
	"fmt"

	networks "github.com/ChayanDass/gobtc-lib/Network"
	pk "github.com/ChayanDass/gobtc-lib/keys/PrivateKey"
)

func main() {
	prvkey, err := pk.NewPrivateKey(networks.Testnet)
	if err != nil {
		fmt.Println("failed to create private key:", err)
		return
	}
	fmt.Println("Generated Private Key:", prvkey.ToString())

	wif := prvkey.ToWIF()
	fmt.Println("WIF:", wif)

	wif1, _ := pk.FromWIF(wif)
	fmt.Println("WIF to Private Key:", wif1.ToString())
}
