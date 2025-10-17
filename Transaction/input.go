package transaction

type TxInput struct {
	TxID        string // ID of the previous transaction (in hex, reversed order for serialization)
	OutputIndex uint32
	Vout        uint32 // Output index in the previous transaction
	ScriptSig   []byte // Unlocking script (scriptSig)
	Sequence    uint32 // Sequence number (for locktime or RBF)
}
