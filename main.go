package main

import (
	"fmt"

	networks "github.com/ChayanDass/gobtc-lib/Network"
	pk "github.com/ChayanDass/gobtc-lib/keys/PrivateKey"
)

func main() {
	networks.SetDefault(networks.Testnet)

	prvkey, err := pk.NewPrivateKey(&pk.KeyOptions{
		Data: "9fb6635efa0bc2cd718ac22a4aedfb7deda6da8d80fdf8e85017cf1deffc2cf8",
	})
	if err != nil {
		fmt.Println("failed to create private key:", err)
		return
	}
	fmt.Println("Generated Private Key:", prvkey.ToString())
	fmt.Println("address", prvkey.ToAddress().ToString())

	// wif := prvkey.ToWIF()
	// fmt.Println("WIF:", wif)

	// wif1, _ := pk.FromWIF(wif)
	// fmt.Println("WIF to Private Key:", wif1.ToString())
}
