package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"syscall"

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

	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [input key file path] [output key file path]\n", cmd[0])
		os.Exit(1)
		return
	}

	in := args[0]
	out := args[1]

	if in == out {
		fmt.Fprintln(os.Stderr, "Output file path must be different from input file path.")
		os.Exit(1)
		return
	}

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

	outFile, err := os.Create(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
		return
	}

	defer outFile.Close()

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

	password, err := hiddenPrompt("Enter your old password")
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

	newPass, err := hiddenPrompt("Enter a new password")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
		return
	}

	confPass, err := hiddenPrompt("Enter new password again to confirm")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
		return
	}

	if confPass != newPass {
		fmt.Fprintln(os.Stderr, "Password mismatch.")
		os.Exit(1)
		return
	}

	encrypted, err := crypt.Encrypt(decrypted, newPass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting new file: %v\n", err)
		os.Exit(1)
		return
	}

	original.Crypto = encrypted
	outJSON, err := json.Marshal(original)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing new file json: %v\n", err)
		os.Exit(1)
		return
	}

	_, err = outFile.Write(outJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing new file: %v\n", err)
		os.Exit(1)
		return
	}

	fmt.Printf("Wrote new file %s\n", out)
}
