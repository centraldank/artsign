package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"io"
	"log"
	"os"
	"time"
)

func hashFile(path string) ([]byte, int64, error) {
	f, err := os.Open(path)
	empty := []byte{}

	if err != nil {
		return empty, 0, err
	}

	defer f.Close()

	h := sha256.New()

	if _, err := io.Copy(h, f); err != nil {
		return empty, 0, err
	}

	info, err := f.Stat()

	if err != nil {
		return empty, 0, err
	}

	return h.Sum(nil)[:], info.Size(), nil
}

type Claim struct {
	Title  string
	Artist string
	Date   string
	Size   uint64
	Sha256 [sha256.Size]byte
}

type Receipt struct {
	Signature [ed25519.SignatureSize]byte
	Claim     []byte
}

func printUsage() {
	fmt.Println("TODO add usage")
}

// var generateCmd = flag.NewFlagSet("generate", flag.ExitOnError)
// var argKeyName = generateCmd.String("keyname", "", "A prefix for generate key names")

var mintCmd = flag.NewFlagSet("mint", flag.ExitOnError)
var privateKeyPath = mintCmd.String("keyfile", "private.key", "Path to a private key file")

var verifyCmd = flag.NewFlagSet("verify", flag.ExitOnError)
var publicKeyPath = mintCmd.String("public", "public.key", "Path to a public key file")

/*
func runGenerateKeys() {
    underscore := ""
    if argKeyName != nil && *argKeyName != "" {
        underscore = "_"
    }

    privatePath := fmt.Sprintf("%s%sprivate.key", *argKeyName, underscore)
    publicPath := fmt.Sprintf("%s%spublic.key", *argKeyName, underscore)

    log.Printf("Generating a keypair '%s' and '%s'\n", privatePath, publicPath)

    public, private, err := ed25519.GenerateKey(nil)
    if (err != nil) {
        log.Printf("Couldn't generate a key pair: #v\n", err);
        return
    }

    pubString := hex.EncodeToString(public)
    priString := hex.EncodeToString(private)

    // Use OpenFile instead of Create to get an error if the file already exists.
    // See https://stackoverflow.com/a/22483001
    f, err := os.OpenFile(publicPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
    if err != nil {
        log.Fatal(err)
    }
    io.WriteString(f, pubString)
    f.Close()

    f, err := os.OpenFile(privatePath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
    if err != nil {
        log.Fatal(err)
    }
    io.WriteString(f, priString)
    f.Close()
}
*/

func main() {

	flag.Parse()

	if len(os.Args) == 1 {
		printUsage()
		flag.Usage()
		return
	}

	switch os.Args[1] {
	//case "generate-keys":
	//    generateCmd.Parse(os.Args[2:])
	//    runGenerateKeys()
	case "mint":
		//filename := os.Args[2]
		mintCmd.Parse(os.Args[2:])
		filename := mintCmd.Arg(0)
		log.Printf("mint! filename: %v, privateKeyPath: %v", filename, *privateKeyPath)
	case "verify":
		verifyCmd.Parse(os.Args[2:])
		log.Printf("verify! publicKeyPath: %v", *publicKeyPath)
	default:
		// This should verify the given file with public.key in default location:
		//  artsign file.png
		if len(os.Args) == 2 {
			verifyCmd.Parse(os.Args[1:])
			log.Printf("verify! publicKeyPath: %v", *publicKeyPath)
		} else {
			printUsage()
			return
		}
	}

	return

	hash, fileSize, err := hashFile("testfiles/aurelius.txt")
	if err != nil {
		log.Fatal(err)
	}
	if len(hash) != sha256.Size {
		log.Fatalf("Hash size was %v!", len(hash))
	}

	fmt.Printf("SHA256: %v\n", hex.EncodeToString(hash))

	title := "A Piece"
	artist := "Bankzy"
	timestamp := time.Now().UTC().Format(time.RFC3339)

	var hashArray [sha256.Size]byte
	copy(hashArray[:], hash)

	c := Claim{
		Title:  title,
		Artist: artist,
		Date:   timestamp,
		Size:   uint64(fileSize), // FIXME int64 -> uint64 cast
		Sha256: hashArray,
	}
	fmt.Printf("%v\n", c)

	claimdoc, err := bson.Marshal(c)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("claimdoc: %#v\n", claimdoc)

	var c2 Claim
	err = bson.Unmarshal(claimdoc, &c2)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("c2: %#v\n", c2)

	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Printf("Couldn't generate a key pair: #v\n", err)
		return
	}
	fmt.Printf("Private key: %#v\nPublic key: %#v\n", private, public)

	pubString := hex.EncodeToString(public)
	priString := hex.EncodeToString(private)

	f, err := os.Create("public.key")
	if err != nil {
		log.Fatal(err)
	}
	io.WriteString(f, pubString)
	f.Close()

	f, err = os.Create("private.key")
	if err != nil {
		log.Fatal(err)
	}
	io.WriteString(f, priString)
	f.Close()

	signature := ed25519.Sign(private, claimdoc)
	verified := ed25519.Verify(public, claimdoc, signature)

	fmt.Printf("Signature: %#v\n", signature)

	if verified {
		fmt.Println("Verified")
	} else {
		fmt.Println("Couldn't verify!")
	}

	var signatureArray [ed25519.SignatureSize]byte
	copy(signatureArray[:], signature)

	receipt := Receipt{
		Signature: signatureArray,
		Claim:     claimdoc,
	}

	doc, err := bson.Marshal(receipt)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Doc %#v\n", doc)

	f, err = os.Create("signed.receipt")

	if err != nil {
		log.Fatal(err)
	}

	f.Write(doc)
	defer f.Close()

}
