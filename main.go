package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"syscall"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	eth2ks "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	"golang.org/x/term"
)

func hiddenPrompt(query string) (string, error) {

	fmt.Printf("%s:", query)
	p, e := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return string(p), e
}

// Encrypted validator keystore following the EIP-2335 standard
// (https://eips.ethereum.org/EIPS/eip-2335)
type Keystore struct {
	Crypto  map[string]interface{} `json:"crypto"`
	Version uint                   `json:"version"`
	UUID    uuid.UUID              `json:"uuid"`
	Path    string                 `json:"path"`
	Pubkey  string                 `json:"pubkey"`
}

func main() {
	cmd := os.Args[:1]
	args := os.Args[1:]

	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [input key file path]\n", cmd[0])
		os.Exit(1)
		return
	}

	in := args[0]

	stat, err := os.Stat(in)

	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "%s: File not found.\n", in)
		os.Exit(1)
		return
	}

	if stat.IsDir() {
		fmt.Fprintf(os.Stderr, "%s is a directory. Please pass a file.\n", in)
		os.Exit(1)
		return
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error stating input file: %v\n", err)
		os.Exit(1)
		return
	}

	originalFile, err := ioutil.ReadFile(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
		os.Exit(1)
		return
	}

	original := Keystore{}
	err = json.Unmarshal(originalFile, &original)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing input file: %v\n", err)
		os.Exit(1)
		return
	}

	kdf, exists := original.Crypto["kdf"]
	if !exists {
		fmt.Fprintf(os.Stderr, "Error parsing input file kdf object: does not exist\n")
		os.Exit(1)
		return
	}

	f, exists := kdf.(map[string]interface{})["function"]
	function := f.(string)
	if !exists {
		fmt.Fprintf(os.Stderr, "Error parsing input file kdf.function string: does not exist\n")
		os.Exit(1)
		return
	}

	fmt.Printf("Loaded keystore for %s\n", original.Pubkey)

	password, err := hiddenPrompt("Enter your keystore password")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
		return
	}

	crypt := eth2ks.New(eth2ks.WithCipher(function))
	if crypt == nil {
		fmt.Fprintf(os.Stderr, "Error: could not initialize eth2ks with kdf function %s\n", function)
		os.Exit(1)
		return
	}

	decrypted, err := crypt.Decrypt(original.Crypto, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting keystore: %v\n", err)
		os.Exit(1)
		return
	}

	fmt.Println("Password correct.")

	mk, err := hdkeychain.NewMaster(decrypted, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create wallet master key: %w", err)
		os.Exit(1)
		return
	}

	path, err := accounts.ParseDerivationPath("m/44'/60'/0'/0/0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not parse derivation path: %w", err)
		os.Exit(1)
		return
	}

	key := mk
	for _, n := range path {
		// goerli
		//key, err = key.DeriveNonStandard(n)
		// Mainnet etc
		key, err = key.Derive(n)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error Deriving path: %w\n", err)
			os.Exit(1)
			return
		}
	}

	privKey, err := key.ECPrivKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get ECPrivKey: %w", err)
		os.Exit(1)
		return
	}
	ecdsaPrivKey := privKey.ToECDSA()
	pubKey := ecdsaPrivKey.Public()
	pubKeyEcdsa, _ := pubKey.(*ecdsa.PublicKey)
	fmt.Printf("Private Key at index 0: %s\n", hex.EncodeToString(privKey.Serialize()))
	fmt.Printf("Public Key at index 0: %v\n", crypto.PubkeyToAddress(*pubKeyEcdsa))
	return
}
