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

func printPossibleOutputs(possibleOutputs []string) {
	for _, word := range possibleOutputs {
		fmt.Printf("\t%v\n", word)
	}
}

// Transforms a string to an array of each character's ASCII value
func toAscii(plaintext string) (asciiStream []int) {
	asciiStream = make([]int, len(plaintext))
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
			code = int(unicode.ToUpper(rune(code)))
			folded = true
		}

		shiftedCode = code + shiftKey

		// Control flow for non alphabet characters
		if !unicode.IsLetter(rune(code)) {
			shiftedCode = code
		} else if shiftedCode < asciiA {
			shiftedCode = asciiZ - (asciiA - shiftedCode - 1)
		} else if shiftedCode > asciiZ {
			shiftedCode = asciiA - (asciiZ - shiftedCode + 1)
		}

		// reverts character case if changed
		if folded {
			shiftedCode = int(unicode.ToLower(rune(shiftedCode)))
		}

		output += string(rune(shiftedCode))
	}
	return output
}

// shift cipher callback
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
		if shiftKey == 0 {
			for shift := 1; shift <= 25; shift++ {
				possibleOutputs = append(possibleOutputs, _shift(message, shift))
			}
			break
		}
		for _, dir := range directions {
			possibleOutputs = append(possibleOutputs, _shift(message, dir*shiftKey))
		}
	}
	fmt.Println("The message is among the following:")
	printPossibleOutputs(possibleOutputs)
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
