package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var rawTx = flag.String("rawtx", "", "hexed raw tx")
var pubkey = flag.String("pubkey", "", "hexed pubkey script")
var intputVal = flag.Int64("val", 0, "input value")

func main() {

	flag.Parse()
	if len(*rawTx) == 0 {
		panic("empty hex tx string")
	}

	if len(*pubkey) == 0 {
		panic("empty hex pubkey script string")
	}

	if *intputVal == 0 {
		panic("0 intput value")
	}

	rawTx, err := hex.DecodeString(*rawTx)
	if err != nil {
		panic(err)
	}
	tx := wire.NewMsgTx(1)
	if err := tx.DeserializeNoWitness(bytes.NewReader(rawTx)); err != nil {
		panic(err)
	}

	fmt.Printf("tx.command = %s\n", tx.Command())
	fmt.Printf("len(tx.in)  = %d\n", len(tx.TxIn))
	fmt.Printf("len(tx.out)  = %d\n", len(tx.TxOut))

	pubkeyScript, err := hex.DecodeString(*pubkey)
	if err != nil {
		panic(err)
	}

	engine, err := txscript.NewEngine(pubkeyScript, tx, 0, 65503, nil, nil, *intputVal)
	if err != nil {
		panic(err)
	}

	err = engine.Execute()

	fmt.Printf("err=%v\n", err)
}
