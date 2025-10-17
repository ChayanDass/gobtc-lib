package main

import (
	networks "ChayanDass/Bitcoin-lib/Network"
	pk "ChayanDass/Bitcoin-lib/keys/PrivateKey"
	"fmt"
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
