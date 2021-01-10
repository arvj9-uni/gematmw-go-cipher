package main

import (
	"fmt"
	"github.com/thatisuday/commando"
	"strconv"
	"strings"
	"unicode"
	_ "unicode"
	"unicode/utf8"
)

const (
	//	File Directories
	commonWords string = "Z:\\GitHub\\gematmw-go-cipher\\assets\\20k-edited"

	//	ASCII codes needed for calculations
	asciiA int = 'A'
	asciiZ int = 'Z'

	englishAlphabetLen int = 26
	base10             int = 10
	bit32              int = 32
)

func main() {
	//	configure commando
	commando.
		SetExecutableName("cipher").
		SetVersion("2.0.0").
		SetDescription("This is a CLI application that encrypts/decrypts messages using different methods that may or may not have been discussed in class.")

	//	configure the affine command
	commando.
		Register("affine").
		AddArgument("message", "message to encrypt/decrypt", "").
		AddFlag("process,p", "encrypt/decrypt", commando.String, "encrypt").
		AddFlag("key,k", "values for a and b for the function input as 'a,b'", commando.String, "1,0").
		SetAction(affineCipher)

	//	configure the atbash command
	commando.
		Register("atbash").
		AddArgument("message", "message to encrypt/decrypt", "").
		AddFlag("process,p", "encrypt/decrypt", commando.String, "encrypt").
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

//	printOutput displays the format for the cipher output.
func printOutput(message interface{}) {
	switch t := message.(type) {
	case string:
		fmt.Println("The transformed message is:")
		fmt.Printf("\t%v", t)
	case []string:
		fmt.Println("The possible message is among these:")
		for _, possibleOutput := range t {
			fmt.Printf("\t%v", possibleOutput)
		}
	}
}

//	parseInput takes the comma separated arguments of key flags
//	as needed.
func parseInput(input string) []int {
	output := make([]int, strings.Count(input, ",")+1)
	for i, coeff := range strings.Split(input, ",") {
		output[i], _ = strconv.Atoi(coeff)
	}
	return output
}

//	This affine function is a helper that may be used by
//	similar ciphers.
func affine(char rune, a int, b int) rune {
	//	Non-alpha Handling
	if isAlpha := unicode.IsLetter(char); isAlpha {
		//	Case Handling
		isUpper := unicode.IsUpper(char)
		if !isUpper {
			char = unicode.ToUpper(char)
		}

		mapped := int(char) - asciiA
		mapped = (a*mapped + b) % englishAlphabetLen
		char = rune(mapped + asciiA)

		if !isUpper {
			char = unicode.ToLower(char)
		}
	}

	return char
}

//	Map returns a copy of the string s with all its characters
//	modified according to the mapping function. This is a
//	modified version of the Map function found in the strings
//	package.
func Map(mapping func(rune, int, int) rune, coefs []int, s string) string {
	//	The output buffer acc is initialized on demand, the
	//	first time a character differs.
	var acc strings.Builder
	for i, char := range s {
		r := mapping(char, coefs[0], coefs[1])
		if r == char && char != utf8.RuneError {
			continue
		}

		var width int
		if char == utf8.RuneError {
			char, width = utf8.DecodeRuneInString(s[i:])
			if width != 1 && r == char {
				continue
			}
		} else {
			width = utf8.RuneLen(char)
		}

		acc.Grow(len(s) + utf8.UTFMax)
		acc.WriteString(s[:i])
		if r >= 0 {
			acc.WriteRune(r)
		}

		s = s[i+width:]
		break
	}

	//	Fast path for unchanged input
	if acc.Cap() == 0 {
		return s
	}

	for _, char := range s {
		r := mapping(char, coefs[0], coefs[1])

		if r >= 0 {
			//	common case
			//	Due to inlining, it is more performant to
			//	determine if WriteByte should be invoked rather
			//	than always call WriteRune
			if r < utf8.RuneSelf {
				acc.WriteByte(byte(r))
			} else {
				//	r is not an ASCII rune.
				acc.WriteRune(r)
			}
		}
	}
	return acc.String()
}

//	The callback function, affineCipher, maps each alphabet
//	letter to a different letter according to an encryption
//	function. E(x) = (a*x + b) % 26: this is done by the affine
//	helper function.
func affineCipher(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	//	initial setup
	message := args["message"].Value
	input, _ := flags["key"].GetString()
	coefs := parseInput(input)

	switch flags["process"].Value {
	case "encrypt":
		message = Map(affine, coefs, message)
	case "decrypt":
		break
	}

	printOutput(message)
}

//	The callback function, atbashCipher, maps each alphabet
//	letter to the reverse in the english alphabet.
func atbashCipher(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	message := args["message"].Value
	coefs := []int{-1, 25}				//	y = -x + 25

	switch flags["process"].Value {
	case "encrypt":
		message = Map(affine, coefs, message)
	case "decrypt":
		message = Map(affine, coefs, message)
	}

	printOutput(message)
}

//	The callback function, shiftCipher, maps each alphabet
//	letter to n-steps in the english alphabet.
func shiftCipher(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	message := args["message"].Value
	key, _ := flags["key"].GetInt()
	coefs := []int{0, key}

	switch flags["process"].Value {
	case "encrypt":
		message = Map(affine, coefs, message)
	case "decrypt":
		message = Map(affine, coefs, message)
	}

	printOutput(message)
}

//	The callback function, vigenereCipher, maps each alphabet
//	letter according to a string key which maps each character
//	differently compared to the regular shift cipher.
func vigenereCipher(_ map[string]commando.ArgValue, _ map[string]commando.FlagValue) {}

//	The callback function, railFenceCipher,
func railFenceCipher(_ map[string]commando.ArgValue, _ map[string]commando.FlagValue) {}

//	The callback function, rsaCipher,
func rsaCipher(_ map[string]commando.ArgValue, _ map[string]commando.FlagValue) {}
