package main

import (
	"fmt"
	"github.com/thatisuday/commando"
	"strconv"
)

const (
	//	ASCII codes needed for calculations
	asciiA int = 'A'
	asciiZ int = 'Z'
)

func main() {
	//	configure commando
	commando.
		SetExecutableName("cipher").
		SetVersion("2.0.0").
		SetDescription("This is a CLI application that encrypts/decrypts messages using different methods that may or may not have been discussed in class.")

	//	configure the atbash command
	commando.
		Register("atbash").
		AddArgument("message", "message to encrypt/decrypt", "").
		SetAction(atbashCipher)

	//	configure the shift command
	commando.
		Register("shift").
		AddArgument("message", "message to encrypt/decrypt", "").
		AddFlag("process,p", "encrypt/decrypt", commando.String, "encrypt").
		AddFlag("key,k", "cipher shift key", commando.Int, 0).
		SetAction(shiftCipher)

	//	configure the vigenère command
	commando.
		Register("vigenere").
		AddArgument("message", "message to encrypt/decrypt", "").
		AddFlag("process,p", "encrypt/decrypt", commando.String, "encrypt").
		AddFlag("key,k", "cipher key", commando.String, "a").
		SetAction(vigenereCipher)

	//	configure the rail fence command
	commando.
		Register("rail").
		AddArgument("message", "message to encrypt/decrypt", "").
		AddFlag("process,p", "encrypt/decrypt", commando.String, "encrypt").
		AddFlag("key,k", "rail fence cipher key", commando.Int, 0).
		SetAction(railFenceCipher)

	//	configure the RSA cryptosystem command
	commando.
		Register("rsa").
		AddArgument("message", "message to encrypt/decrypt", "").
		AddFlag("process,p", "encrypt/decrypt", commando.String, "encrypt").
		AddFlag("public,e", "RSA cipher public key", commando.Int, 0).
		AddFlag("private,d", "RSA cipher private key", commando.Int, 0).
		SetAction(rsaCipher)

	//	parse command-line arguments
	commando.Parse(nil)
}

//	The callback function, atbashCipher, maps each character to
//	the reverse in the english alphabet.
func atbashCipher(args map[string]commando.ArgValue, _ map[string]commando.FlagValue) {
	var message string = args["message"].Value
	fmt.Println(message)
}

//	The callback function, shiftCipher, maps each character to
//	n-steps in the english alphabet.
func shiftCipher(_ map[string]commando.ArgValue, _ map[string]commando.FlagValue) {}

//	The callback function, vigenereCipher, maps
func vigenereCipher(_ map[string]commando.ArgValue, _ map[string]commando.FlagValue) {}

//	The callback function, railFenceCipher,
func railFenceCipher(_ map[string]commando.ArgValue, _ map[string]commando.FlagValue) {}

//	The callback function, rsaCipher,
func rsaCipher(_ map[string]commando.ArgValue, _ map[string]commando.FlagValue) {}
