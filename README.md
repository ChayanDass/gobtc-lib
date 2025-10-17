# GoBTC Library

GoBTC is a lightweight Go library for Bitcoin wallet management and key handling.  
Currently, **only legacy wallets (P2PKH)** are supported.

---

## Features

- Generate new private keys
- Derive public keys from private keys
- Export/import private keys in WIF (Wallet Import Format)
- Generate Bitcoin addresses (legacy P2PKH)
- Human-readable key serialization
- Go-native BN-like handling for private key scalars (ModNScalar)

---

## Installation

Install via `go get`:

```bash
go get github.com/ChayanDass/gobtc-lib
