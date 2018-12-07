package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/andlabs/ui"
	. "github.com/elastos/Elastos.ELA.Utility/common"
	"github.com/elastos/Elastos.ELA.Utility/crypto"
	. "github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ORG.API.Misc/log"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var(
	mainwin *ui.Window
	w wallet
	curr  string
	right string
	file string
	txid string
	host = "http://localhost"
	port = "21334"
)

const (
	ELA float64 = 100000000
	PLACEHORDER_PRIVKEY = "(private Key)"
)

type wallet struct {
	privKey []byte
	pubKey  *crypto.PublicKey
	redeemScript []byte
	address string
}
type receiver struct{
	Address string
	Amount  *Fixed64
}

type UTXO struct {
	Txid string
	Index float64
	Value string
}
type txResult struct {
	Desc string
	Error float64
	Result string
}

func pageOne(){
	vBox := ui.NewVerticalBox()
	vBox.SetPadded(true)
	tab := ui.NewTab()
	tab.Append("Node Info",vBox)
	tab.SetMargined(0,true)
	mainwin.SetChild(tab)
	mainwin.SetMargined(true)
	group := ui.NewGroup("")
	group.SetMargined(true)
	vBox.Append(group, true)

	entryForm := ui.NewForm()
	entryForm.SetPadded(true)
	group.SetChild(entryForm)

	entry := ui.NewEntry()
	entry.SetText(host)
	entry.OnChanged(func(entry *ui.Entry) {
		host = entry.Text()
	})
	entryForm.Append("Host Ip", entry, false)
	portEntry := ui.NewEntry()
	portEntry.OnChanged(func(entry *ui.Entry) {
		port = entry.Text()
	})
	portEntry.SetText(port)
	entryForm.Append("Restful Port", portEntry, false)
	btn := ui.NewButton("Submit")
	entryForm.Append("",btn,false)
	btn.OnClicked(pageTwo)
}

func setupUI(){
	mainwin = ui.NewWindow("Elastos Wallet", 640, 480, true)
	mainwin.OnClosing(func(*ui.Window) bool {
		ui.Quit()
		return true
	})
	ui.OnShouldQuit(func() bool {
		mainwin.Destroy()
		return true
	})
	defer mainwin.Show()

	pageOne()
}

func pageTwo(button *ui.Button){
	timeout := time.Duration(5 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}
	r , err := client.Get(host+":"+port+"/api/v1/block/height")
	if err != nil || (r != nil && r.StatusCode != 200){
		ui.MsgBoxError(mainwin,
			"Error",
			"Not valid configuration.")
		return
	}
	tab := ui.NewTab()
	tab.Append("Create Wallet",makeWallet())
	tab.SetMargined(0,true)
	tab.Append("import Wallet",importWallet())
	tab.SetMargined(1,true)
	mainwin.SetChild(tab)
	mainwin.SetMargined(true)
}



func recorver(privKey string) error{
	priv := new(ecdsa.PrivateKey)
	c := elliptic.P256()
	priv.PublicKey.Curve = c
	k := new(big.Int)
	privKeyBytes , err := hex.DecodeString(privKey)
	if err != nil {
		return err
	}
	k.SetBytes(privKeyBytes)
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	publicKey := new(crypto.PublicKey)
	publicKey.X = new(big.Int).Set(priv.PublicKey.X)
	publicKey.Y = new(big.Int).Set(priv.PublicKey.Y)
	redeemScript , err := crypto.CreateStandardRedeemScript(publicKey)
	if err != nil {
		return err
	}
	hash, _ := crypto.ToProgramHash(redeemScript)
	addr, _ := hash.ToAddress()
	w = wallet{privKey:privKeyBytes,pubKey:publicKey,address:addr,redeemScript:redeemScript}
	return nil
}

func createWallet(){
	priv , pubKey , err := crypto.GenerateKeyPair()
	if err != nil {
		println(err.Error())
		return
	}
	redeemScript , err := crypto.CreateStandardRedeemScript(pubKey)
	if err != nil {
		println(err.Error())
		return
	}
	pubHex := hex.EncodeToString(redeemScript[1:len(redeemScript)-1])
	publicKey, err := hex.DecodeString(pubHex)
	pub, _ := crypto.DecodePoint(publicKey)
	code, _ := crypto.CreateStandardRedeemScript(pub)
	hash, _ := crypto.ToProgramHash(code)
	addr, _ := hash.ToAddress()
	w = wallet{privKey:priv,pubKey:pubKey,address:addr,redeemScript:redeemScript}
}


func importWallet() ui.Control{

	vbox := ui.NewVerticalBox()
	vbox.SetPadded(true)

	entry := ui.NewEntry()
	entry.SetText(PLACEHORDER_PRIVKEY)
	handlePrivEty(entry)

	vbox.Append(entry,false)
	grid := ui.NewGrid()
	grid.SetPadded(true)
	vbox.Append(grid, false)



	msggrid := ui.NewGrid()
	msggrid.SetPadded(true)
	grid.Append(msggrid,
		0, 2, 2, 1,
		false, ui.AlignCenter, false, ui.AlignStart)

	button := ui.NewButton("Submit")
	button.OnClicked(func(*ui.Button) {
		if len(curr) != 64 {
			ui.MsgBoxError(mainwin,"Error","Invalid private key")
			return
		}
		err := recorver(right)
		if err != nil {
			ui.MsgBoxError(mainwin,"Error","Invalid private key")
			return
		}
		mainframe()
	})
	msggrid.Append(button,
		0, 0, 1, 1,
		false, ui.AlignFill, false, ui.AlignFill)

	return vbox
}

func handlePrivEty(privEty *ui.Entry){
	privEty.OnChanged(func(entry *ui.Entry) {
		key := entry.Text()
		if strings.Index(key,PLACEHORDER_PRIVKEY) == 0 {
			entry.SetText(strings.Replace(key,"(private Key)","",1))
			return
		}
		curr = key
		if len(key) == 64 {
			right = key
		}
		if len(key) > 64 {
			entry.SetText(right)
		}
	})
}

func makeWallet() ui.Control{

	vbox := ui.NewVerticalBox()
	vbox.SetPadded(true)

	grid := ui.NewGrid()
	grid.SetPadded(true)
	vbox.Append(grid, false)

	button := ui.NewButton("Generate")
	entry := ui.NewEntry()
	entry.SetText(PLACEHORDER_PRIVKEY)
	entry.SetReadOnly(true)

	entry2 := ui.NewEntry()
	entry2.SetText("(Address)")
	entry2.SetReadOnly(true)

	button.OnClicked(func(*ui.Button) {
		createWallet()
		entry.SetText(hex.EncodeToString(w.privKey))
		entry2.SetText(w.address)
	})

	grid.Append(button,
		0, 0, 1, 1,
		false, ui.AlignFill, false, ui.AlignFill)
	grid.Append(entry,
		1, 0, 1, 1,
		true, ui.AlignFill, false, ui.AlignFill)


	grid.Append(entry2,
		1, 1, 1, 1,
		false, ui.AlignFill, false, ui.AlignFill)

	msggrid := ui.NewGrid()
	msggrid.SetPadded(true)
	grid.Append(msggrid,
		0, 2, 2, 1,
		false, ui.AlignCenter, false, ui.AlignStart)

	button = ui.NewButton("Submit")
	button.OnClicked(func(*ui.Button) {
		mainframe()
	})
	msggrid.Append(button,
		0, 0, 1, 1,
		false, ui.AlignFill, false, ui.AlignFill)

	return vbox
}

func handleFile(filename string) (string , error) {
	f, err := os.Open(filename)
	if err != nil {
		return "",err
	}
	b , err := ioutil.ReadAll(f)
	if err != nil {
		return "",err
	}
	var rf []receiver
	err = json.Unmarshal(b,&rf)
	if err != nil {
		return "",errors.New("Invalid File Format")
	}
	return send(rf)
}

func send(rf []receiver) (string,error){
	if rf == nil || len(rf) == 0 {
		return "",errors.New("Invalid File format")
	}
	tx , err := createTransaction(w.address,rf...)
	if err != nil {
		return "",err
	}
	rawTx , err := sign(tx)
	if err != nil {
		return "",err
	}
	return sendRawTx(rawTx)
}

func sendRawTx(rawTx string) (string,error){
	return call("sendrawtransaction", rawTx)
}

func call(method string, rawData string) (string, error) {
	data, err := json.Marshal(map[string]interface{}{
		"method": method,
		"data": rawData,
	})
	if err != nil {
		return "", err
	}

	resp, err := http.Post(host+":"+port+"/api/v1/transaction", "application/json", strings.NewReader(string(data)))
	if err != nil {
		fmt.Printf("POST requset: %v\n", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func createTransaction(fromAddress string, outputs ...receiver) (*Transaction, error) {

	// Check if from address is valid
	spender, err := Uint168FromAddress(fromAddress)
	if err != nil {
		return nil, err
	}
	// Create transaction outputs
	var totalOutputAmount = Fixed64(0) // The total amount will be spend
	var txOutputs []*Output            // The outputs in transaction
	totalOutputAmount += 100          // Add transaction fee

	assetId , _ := Uint256FromHexString("a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0")
	assetId , _ = Uint256FromBytes(BytesReverse(assetId[:]))
	for _, output := range outputs {
		receiver, err := Uint168FromAddress(output.Address)
		if err != nil {
			return nil,err
		}
		txOutput := &Output{
			AssetID:    *assetId,
			ProgramHash: *receiver,
			Value:     *output.Amount,
			OutputLock:  0,
		}
		totalOutputAmount += *output.Amount
		txOutputs = append(txOutputs, txOutput)
	}
	// Get spender's UTXOs
	UTXOs, err := GetAddressUTXOs(fromAddress)
	if err != nil{
		return nil, err
	}

	// Create transaction inputs
	var txInputs []*Input // The inputs in transaction
	for _, utxo := range UTXOs {
		uint256Utxo,_:=Uint256FromHexString(utxo.Txid)

		input := &Input{
			Previous: OutPoint{
				TxID:  *reverseBytes(*uint256Utxo),
				Index: uint16(utxo.Index),
			},
			Sequence: 0,
		}
		txInputs = append(txInputs, input)
		utxoValue , _ := strconv.ParseFloat(utxo.Value,64)
		v := Fixed64(utxoValue * ELA)
		if v < totalOutputAmount {
			totalOutputAmount -= v
		} else if v == totalOutputAmount {
			totalOutputAmount = 0
			break
		} else if v > totalOutputAmount {
			change := &Output{
				AssetID:     *assetId,
				Value:       v - totalOutputAmount,
				OutputLock:  uint32(0),
				ProgramHash: *spender,
			}
			txOutputs = append(txOutputs, change)
			totalOutputAmount = 0
			break
		}
	}
	if totalOutputAmount > 0 {
		return nil, errors.New("[Wallet], Available token is not enough")
	}

	return newTransaction(w.redeemScript, txInputs, txOutputs), nil
}

func sign(txn *Transaction) (string,error){
	// Sign transaction
	buf := new(bytes.Buffer)
	txn.SerializeUnsigned(buf)
	signedTx, err := crypto.Sign(w.privKey, buf.Bytes())
	if err != nil {
		return "",err
	}
	// Add verify program for transaction
	buf = new(bytes.Buffer)
	buf.WriteByte(byte(len(signedTx)))
	buf.Write(signedTx)
	// Add signature
	txn.Programs[0].Parameter = buf.Bytes()
	buf = new(bytes.Buffer)
	txn.Serialize(buf)
	content := BytesToHexString(buf.Bytes())

	return content,nil
}

func newTransaction(redeemScript []byte, inputs []*Input, outputs []*Output) *Transaction {
	// Create payload
	txPayload := &PayloadTransferAsset{}
	// Create attributes
	txAttr := NewAttribute(Nonce, []byte(strconv.FormatInt(rand.Int63(), 10)))
	attributes := make([]*Attribute, 0)
	attributes = append(attributes, &txAttr)
	// Create program
	var program = &Program{redeemScript, nil}
	// Create transaction
	return &Transaction{
		TxType:     TransferAsset,
		Payload:    txPayload,
		Attributes: attributes,
		Inputs:     inputs,
		Outputs:    outputs,
		Programs:   []*Program{program},
		LockTime:   0,
	}
}


func GetAddressUTXOs(fromAddress string) ([]UTXO,error){
	r , err := http.Get(host+":"+port+"/api/v1/asset/utxos/"+fromAddress)
	if err != nil {
		return nil,err
	}
	b , err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil,err
	}
	var data map[string]interface{}
	err = json.Unmarshal(b,&data)
	if err != nil {
		return nil,err
	}
	rst , ok := data["Result"].([]interface{})
	if !ok {
		return []UTXO{},errors.New("NO Enough UTXO")
	}
	utxosRst := rst[0].(map[string]interface{})["Utxo"].([]interface{})
	b , err = json.Marshal(utxosRst)
	var utxos []UTXO
	err = json.Unmarshal(b,&utxos)
	if err != nil {
		return nil,err
	}
	return utxos,nil
}

func mainframe() {

	hbox := ui.NewHorizontalBox()
	hbox.SetPadded(true)

	vbox := ui.NewVerticalBox()
	vbox.SetPadded(true)
	vbox.Append(ui.NewLabel("Address : " + w.address),false)
	vbox.Append(ui.NewVerticalSeparator(),false)
	hbox.Append(vbox, true)

	grid := ui.NewGrid()
	grid.SetPadded(true)
	vbox.Append(grid, false)

	button := ui.NewButton("Open File")
	entry := ui.NewEntry()
	entry.SetReadOnly(true)
	button.OnClicked(func(*ui.Button) {
		filename := ui.OpenFile(mainwin)
		if filename == "" {
			filename = "(cancelled)"
		}else{
			file = filename
		}
		entry.SetText(filename)
	})
	grid.Append(button,
		0, 0, 1, 1,
		false, ui.AlignFill, false, ui.AlignFill)
	grid.Append(entry,
		1, 0, 1, 1,
		true, ui.AlignFill, false, ui.AlignFill)

	txidBtn := ui.NewButton("Txid")
	txidBtn.Hide()
	entry2 := ui.NewEntry()
	entry2.Hide()
	entry2.SetReadOnly(true)
	grid.Append(txidBtn,
		0, 1, 1, 1,
		false, ui.AlignFill, false, ui.AlignFill)
	grid.Append(entry2,
		1, 1, 1, 1,
		false, ui.AlignFill, false, ui.AlignFill)
	msggrid := ui.NewGrid()
	msggrid.SetPadded(true)
	grid.Append(msggrid,
		0, 2, 2, 1,
		false, ui.AlignCenter, false, ui.AlignStart)

	button = ui.NewButton("Send")
	button.OnClicked(func(*ui.Button) {
		result , err := handleFile(file)
		if err != nil {
			ui.MsgBoxError(mainwin,"Error",err.Error())
		}else{
			//ui.MsgBox(mainwin,"Success",txid)
			var r txResult
			json.Unmarshal([]byte(result),&r)
			if r.Error == 0 {
				entry2.SetText(r.Result)
				entry2.Show()
				txidBtn.Show()
			}else{
				ui.MsgBoxError(mainwin,"Error",r.Desc)
			}
		}
	})
	msggrid.Append(button,
		0, 0, 1, 1,
		false, ui.AlignFill, false, ui.AlignFill)
	button = ui.NewButton("Back")
	button.OnClicked(pageTwo)
	msggrid.Append(button,
		1, 0, 1, 1,
		false, ui.AlignFill, false, ui.AlignFill)

	mainwin.SetChild(hbox)
}

func reverseBytes(src Uint256)(*Uint256){
	rst := make([]byte,32)
	for i:= 0 ; i < len(src);i++ {
		rst[i] = src[len(src)-1-i];
	}
	ret , _ := Uint256FromBytes(rst)
	return ret
}

func main(){
	ui.Main(setupUI)
}


func init(){
	log.InitLog(0,0)
}