/*
Package gematmw-go-cipher is a CLI tool that encrypts and
decrypts messages using different cipher methods.
*/

package main

import (
	"bufio"
	"fmt"
	"github.com/thatisuday/commando"
	"os"
	"strings"
	"unicode"
)

const (
	mostCommonWords           = "Z:\\GitHub\\gematmw-go-cipher\\resources\\google-10000-english\\20k.txt"
	englishAlphabetLength     = 26
	ascii_a               int = 'a'
	ascii_z               int = 'z'
	//space  int = ' '

)

//	The scanLines function scans a text file line-by-line and
//	returns each line in a string slice.
func scanLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = file.Close(); err != nil {
			panic(err)
		}
	}()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, nil
}

func hasWord(str string) bool {
	words, err := scanLines(mostCommonWords)
	if err != nil {
		panic(err)
	}

	for _, field := range strings.Fields(str) {
		for _, word := range words {
			if field == word {
				fmt.Print(field)
				return true
			}
		}
	}
	return false
}

//	Filters possible outputs that do not contain any english
//	word using the chosen dataset.
func filterGibberish(possibleOutputs []string) []string {
	var outputs []string
	for _, possibleOutput := range possibleOutputs {
		if hasWord(possibleOutput) {
			outputs = append(outputs, possibleOutput)
		}
	}
	return outputs
}

func printOutputs(outputs []string) {
	for _, word := range outputs {
		fmt.Printf("\t%v\n", word)
	}
}

//	Transforms a string to an array of each character's ASCII
//	value.
func toAscii(plaintext string) (asciiStream []int) {
	asciiStream = make([]int, len(plaintext))
	for pos := 0; pos < len(asciiStream); pos++ {
		asciiStream[pos] = int(plaintext[pos])
	}
	return
}

//	The atbash cipher maps each character of an alphabet to
//	its reverse such that the first letter becomes the last
//	letter, the second letter becomes the second to the last
//	letter, and so on.
func atbashCipher(args map[string]commando.ArgValue, _ map[string]commando.FlagValue) {
	// copies of arguments
	message := args["message"].Value

	output := []string{""}
	for _, code := range toAscii(message) {
		// Handles uppercase lowercase situations
		var folded bool
		if unicode.IsLower(rune(code)) {
			code = int(unicode.ToUpper(rune(code)))
			folded = true
		}

		// [Atbash Cipher Encryption/Decryption Function](https://en.wikipedia.org/wiki/Atbash#Relationship_to_the_affine_cipher)
		code -= ascii_a
		code = (englishAlphabetLength - 1) * (code + 1) % englishAlphabetLength
		code += ascii_a

		// Reverts character case if folded
		if folded {
			code = int(unicode.ToLower(rune(code)))
		}
		output[0] += string(rune(code))
	}

	fmt.Println("The message is now:")
	printOutputs(output)
}

//	The shift cipher maps each character to the nth character
//	from the original character.
func _shift(message string, shiftKey int) string {
	var output string
	var shiftedCode int
	for _, code := range toAscii(message) {
		// Handles uppercase lowercase situations
		var folded bool
		if unicode.IsUpper(rune(code)) {
			code = int(unicode.ToLower(rune(code)))
			folded = true
		}

		shiftedCode = code + shiftKey

		// Control flow for non alphabet characters
		if !unicode.IsLetter(rune(code)) {
			shiftedCode = code
		} else if shiftedCode < ascii_a {
			shiftedCode = ascii_z - (ascii_a - shiftedCode - 1)
		} else if shiftedCode > ascii_z {
			shiftedCode = ascii_a - (ascii_z - shiftedCode + 1)
		}

		// reverts character case if changed
		if folded {
			shiftedCode = int(unicode.ToUpper(rune(shiftedCode)))
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

	// encryption and decryption handling
	switch flags["process"].Value {
	case "encrypt":
		for _, dir := range directions {
			possibleOutputs = append(possibleOutputs, _shift(message, dir*shiftKey))
		}
	case "decrypt":
		// missing shift key
		if shiftKey == 0 {
			for shift := 1; shift <= 25; shift++ {
				possibleOutputs = append(possibleOutputs, _shift(message, shift))
			}

			possibleOutputs = filterGibberish(possibleOutputs)
			break
		}

		// when shift key is provided
		for _, dir := range directions {
			possibleOutputs = append(possibleOutputs, _shift(message, dir*shiftKey))
		}

		possibleOutputs = filterGibberish(possibleOutputs)
	}

	fmt.Println("The message is among the following:")
	printOutputs(possibleOutputs)
}

func main() {
	// configure commando
	commando.
		SetExecutableName("cipher").
		SetVersion("1.0.0").
		SetDescription("This CLI application allows one to encrypt and decrypt messages.")

	// configure the atbash command
	commando.
		Register("atbash").
		AddArgument("message", "message to encrypt/decrypt", "").
		SetAction(atbashCipher)

	// configure the shift command
	commando.
		Register("shift").
		AddArgument("message", "message to encrypt/decrypt", "").
		AddFlag("process,p", "encrypt/decrypt", commando.String, "encrypt").
		AddFlag("key,k", "shift key", commando.Int, 0).
		SetAction(shiftCipher)

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
