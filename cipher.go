package main

import (
	"fmt"
	"github.com/thatisuday/commando"
	"unicode"
)

const (
	asciiA int = 'A'
	asciiZ int = 'Z'
	//space  int = ' '
)

func toAscii(plaintext string) (asciiStream []int) {
	for pos := 0; pos < len(asciiStream); pos++ {
		asciiStream[pos] = int(plaintext[pos])
	}
	return
}

// shift cipher helper function
func _shift(message string, shiftKey int) string {
	var output string
	var shiftedCode int
	for _, code := range toAscii(message) {
		// Handles uppercase lowercase situations
		var folded bool
		if unicode.IsLower(rune(code)) {
			code = int(unicode.SimpleFold(rune(code)))
			folded = true
			fmt.Println(code)
		}

		shiftedCode = code + shiftKey
		if !unicode.IsLetter(rune(code)) {
			shiftedCode = code
			fmt.Printf("%v\n",rune(code))
		} else if shiftedCode < asciiA {
			shiftedCode = asciiZ - (asciiA - shiftedCode - 1)
		} else if shiftedCode > asciiZ {
			shiftedCode = asciiA - (asciiZ - shiftedCode + 1)
		}
		if folded {
			shiftedCode = int(unicode.SimpleFold(rune(shiftedCode)))
		}
		output += string(rune(shiftedCode))
		fmt.Println("I passed!")
		fmt.Println(output)
	}
	return output
}

func shiftCipher(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	// copies of arguments
	message := args["message"].Value
	shiftKey, _ := flags["key"].GetInt()

	// init setup for loop
	directions := [2]int{-1, 1}
	var possibleOutputs []string
	switch flags["process"].Value {
	case "encrypt":
		for _, dir := range directions {
			possibleOutputs = append(possibleOutputs, _shift(message, dir*shiftKey))
		}
	case "decrypt":
		if shiftKey != 0 {

		}
	}
	fmt.Printf("The message is either:\n\t%v of length %v", possibleOutputs, len(possibleOutputs))
}

func main() {
	// configure commando
	commando.
		SetExecutableName("cipher").
		SetVersion("1.0.0").
		SetDescription("This CLI application allows one to encrypt and decrypt messages.")

	// configure the shift command
	commando.
		Register("shift").
		AddArgument("message", "message to encrypt/decrypt", "").
		AddFlag("process,p", "encrypt/decrypt", commando.String, "encrypt").
		AddFlag("key,k", "shift key", commando.Int, 0).
		SetAction(shiftCipher)

	// configure the shift command
	//commando.
	//	Register("atbash").
	//	AddArgument("message", "message to encrypt/decrypt", "").
	//	AddFlag("process,p", "encrypt/decrypt", commando.String, "encrypt").
	//	AddFlag("key,k", "shift key", commando.Int, 0).
	//	SetAction(atbashCipher)
	//
	//// configure the shift command
	//commando.
	//	Register("vigenere").
	//	AddArgument("message", "message to encrypt/decrypt", "").
	//	AddFlag("process,p", "encrypt/decrypt", commando.String, "encrypt").
	//	AddFlag("key,k", "shift key", commando.String, "A").
	//	SetAction(vigenereCipher)
	//
	//// configure the shift command
	//commando.
	//	Register("rail").
	//	AddArgument("message", "message to encrypt/decrypt", "").
	//	AddFlag("process,p", "encrypt/decrypt", commando.String, "encrypt").
	//	AddFlag("key,k", "shift key", commando.Int, 0).
	//	SetAction(railFenceCipher)
	//
	//// configure the shift command
	//commando.
	//	Register("rsa").
	//	AddArgument("message", "message to encrypt/decrypt", "").
	//	AddFlag("process,p", "encrypt/decrypt", commando.String, "encrypt").
	//	AddFlag("key,k", "shift key", commando.Int, 0).
	//	SetAction(RSACipher)

	// parse command-line arguments
	commando.Parse(nil)
}
