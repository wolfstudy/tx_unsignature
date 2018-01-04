package main

import "fmt"

type TxSignature struct {
	Version      int32
	flag         uint8
	tx_in_count  int
	tx_in        TX_in
	tx_out_count int
	tx_out       TX_out
	tx_witnesses []byte
	lock_time    uint32
}

type TX_in struct {
	previous_output  OutPoint
	script_length    int
	signature_script []byte
	sequence         uint32
}

type OutPoint struct {
	hash  []byte
	index uint32
}

type TX_out struct {
	value         int64
	pk_script_len int
	pk_script     []byte
}

func analyzeTran ()  {
	rawtx := "0200000001f84cac121e295d364348506030a950f24943c81a38f6e33bc4299dff1621f6f3030000006b483045022100e04f953dd1ccd5a4b6347358247ce4493066ceea2643a6610e9cfae9b4f43613022050e411ce9727ee281ab23dc442d724231cbf2b76c1c6a6d66615b0f592dd4467012103c55488380069a1fac42de5a4c3c2aa04de6cbb2966650a81b5d46a882611e3c2ffffffff08106c0200000000001976a914676bbbbca3b13cf992a395efbf7fe4d203e99cd888ac53f06d00000000001976a914b048d14715829cef2c65aeddc978a58fc2ceb1b788ac3b971b000000000017a914f7c651903cfae4f7ad994a1b1c92303a45dd48d28780b2e60e000000001976a9143f24e96cc0875e67492de1283a8eb334095002e888ac0410db18000000001976a9141c4b2cc45bdb8baa60fa43f6b771e366905ea53188acd6850200000000001976a91420c312c8df612c806917e7fe53e65bb2e2bf12db88acdc2e2d00000000001976a914d33036dc7a1256e717ac8fe6611f786bf81d613c88acc0eb1200000000001976a914dbe0aaa15e08d91d1b79d71aa817de71db6f515288ac00000000"
	fmt.Println(rawtx)
}
