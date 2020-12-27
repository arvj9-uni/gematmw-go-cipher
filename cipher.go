package main

import (
	"fmt"
	"github.com/thatisuday/commando"
	"unicode"
)

const (
	asciiA = int('A')
	asciiZ = int('Z')
)

func toAscii(plaintext string) (asciiStream []int) {
	for pos := 0; pos < len(asciiStream); pos++ {
		asciiStream[pos] = int(plaintext[pos])
	}
	return
}

func shiftCipher(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	message := args["message"].Value
	shiftKey, _ := flags["key"].GetInt()

	var output string
	var shiftedCode int
	possibleOutputs := make([]string, 2)
	directions := []int{-1, 1}
	switch flags["process"].Value {
	case "encrypt":
		for pos, dir := range directions {
			output = ""
			for _, code := range toAscii(message) {
				shiftedCode = code + dir*shiftKey
				if !unicode.IsLetter(rune(code)) {
					shiftedCode = code
				} else if shiftedCode < asciiA {
					shiftedCode = asciiZ - (asciiA - shiftedCode - 1)
				} else if shiftedCode > asciiZ {
					shiftedCode = asciiA - (asciiZ - shiftedCode + 1)
				}
				output += string(rune(shiftedCode))
			}
			possibleOutputs[pos] = output
		}
	}
	fmt.Printf("The message is either:\n\t%v", possibleOutputs)
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

	// parse command-line arguments
	commando.Parse(nil)
}
