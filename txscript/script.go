package main

import (
	"fmt"
	"bytes"
	"strings"
	"net/http"
	"io/ioutil"
	"encoding/hex"
	"btcd/txscript"

	"github.com/gjson"
	"github.com/juju/errors"
	"github.com/btcsuite/btcd/wire"
)

func main() {

	rawtx := "010000000116f70d718db1c032e915dfefb25eafeef1cdc46d6e43ab7320890eb9c033e37d00000000fdfe00004830450221009c6c6af600bdb2b918ecb595a0bcae41881eb771da92e4ba4a05ef17249527f402200d105bbb3c462fbb1ab941697a503fb7a9e48bda5a910959e21f11ff213cde5401483045022100d516c3d638076da7b5fdcc8f2fa1914c5caf6548e3cd2efb16a16605b79321230220062991654aed0966b6b3684141583ef0b188043fce867d633abeac653f487337014c695221028bb6ee1127a620219c4f6fb22067536649d439929e177ebfe76386dff52a70842102f9cd8728b12b6c8a17a15cb4a19de000641f78a449c1b619dc271b84643ce0e92103d33aef1ae9ecfcfa0935a8e34bb4a285cfaad1be800fc38f9fc869043c1cbee253aefeffffff01a09b9a62000000001976a914005ee55b3430bc1a882321efcc5cf898a9aeba5988aca9a70700"

	//去除一下空格
	rawtx = strings.Replace(rawtx," ","",-1)

	res, err := parseMultSig(rawtx)
	if err != nil {
		errors.New("parse failed,please check the rawTx isTrue")
	}

	fmt.Println("the sig address is :\n", res)

}

//解析多重签名
func parseMultSig(rawtx string) ([][]string, error) {
	txscript.Result = [][]string{}

	rawTx, err := hex.DecodeString(rawtx)
	if err != nil {
		errors.New("decode the rawTX failed..")
	}

	//创建tx
	tx := wire.NewMsgTx(1)
	if err := tx.DeserializeNoWitness(bytes.NewReader(rawTx)); err != nil {
		errors.New("create tx struct failed...please check the rawTX type..")
	}

	//锁定脚本
	txidx := tx.TxHash()                   //交易hash
	scripts := getPkScript(txidx.String()) //去输出中寻找锁定脚本

	//txscript.Result = make([][]string, 0)
	for index, value := range scripts {
		//txscript.Result[index] = make([]string, 0)
		temp := make([]string, 0)
		temp = append(temp, hex.EncodeToString(tx.TxIn[index].SignatureScript))
		txscript.Result = append(txscript.Result, temp)

		fmt.Println("Input:", index)
		pubkeyScript, err := hex.DecodeString(value.String())
		if err != nil {
			errors.New("decode the publicKeyScript failed..")
		}

		//创建engine来执行交易
		engine, err := txscript.NewEngine(pubkeyScript, tx, index, 65503, nil, nil, 0)
		if err != nil {
			errors.New("create engine failed. please retry...")
		}

		err = engine.Execute()
		fmt.Printf("err=%v\n", err)

	}

	fmt.Printf("tx.command = %s\n", tx.Command())
	fmt.Printf("len(tx.in)  = %d\n", len(tx.TxIn))
	fmt.Printf("len(tx.out)  = %d\n", len(tx.TxOut))
	fmt.Printf("version: %d\n", tx.Version)
	fmt.Printf("LockTime: %d\n", tx.LockTime)
	return txscript.Result, nil
}

func getPkScript(txidx string) []gjson.Result {
	var btcApiPrefix = "https://blockchain.info/rawtx/"
	rawContent, err := http.Get(btcApiPrefix + txidx)
	if err != nil {
		errors.New("get the request failed, please check the network...")
	}

	defer rawContent.Body.Close()
	content, _ := ioutil.ReadAll(rawContent.Body)

	result := gjson.Get(string(content), "inputs.#.prev_out.script").Array()

	return result
}
