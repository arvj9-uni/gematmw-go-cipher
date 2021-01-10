package main

import (
	"bufio"
	"fmt"
	"github.com/thatisuday/commando"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	//	File Directories
	mostCommonWords string = "Z:\\GitHub\\gematmw-go-cipher\\assets\\20k-edited-1k.txt"

	//	ASCII codes needed for calculations
	asciiA int = 'A'

	englishAlphabetLen int = 26
)

func main() {
	//	configure commando
	commando.
		SetExecutableName("ciphers").
		SetVersion("2.0.0").
		SetDescription("This is a CLI application that encrypts/decrypts messages using different methods that may or may not have been discussed in class. The interface is based on the commando package in https://github.com/thatisuday/commando")

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

//	hasWord checks whether an output contains an actual
//	existing word based on the firs 1_000 words from
//	https://github.com/arvj9-uni/google-10000-english
func hasWord(str string) bool {
	words, err := scanLines(mostCommonWords)
	if err != nil {
		panic(err)
	}

	for _, field := range strings.Fields(str) {
		for _, word := range words {
			if strings.ToLower(field) == word {
				fmt.Println(field)
				return true
			}
		}
	}
	return false
}

//	filterGibberish removes any output that does not satisfy
//	the hasWord method
func filterGibberish(possibleOutputs []string) []string {
	var outputs []string
	for _, possibleOutputs := range possibleOutputs {
		if hasWord(possibleOutputs) {
			outputs = append(outputs, possibleOutputs)
		}
	}
	return outputs
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
func Map(mapping func(rune, int, int) rune, coefficients []int, s string) string {
	//	The output buffer acc is initialized on demand, the
	//	first time a character differs.
	var acc strings.Builder
	for i, char := range s {
		r := mapping(char, coefficients[0], coefficients[1])
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
		r := mapping(char, coefficients[0], coefficients[1])

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
	coefficients := parseInput(input)

	switch flags["process"].Value {
	case "encrypt":
		message = Map(affine, coefficients, message)
	case "decrypt":
		break
	}

	printOutput(message)
}

//	The callback function, atbashCipher, maps each alphabet
//	letter to the reverse in the english alphabet. The affine
//	cipher system is used as a helper for this cipher as they
//	relate to each other via the equation: E(x) = (-x + 25) mod26,
//	which is achieved when plotting the (input, output) of the
//	atbashCipher and determining the linear equation for it.
func atbashCipher(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	message := args["message"].Value
	coefficients := []int{-1, 25} //	y = (-x + 25) mod26

	switch flags["process"].Value {
	case "encrypt":
		message = Map(affine, coefficients, message)
	case "decrypt":
		message = Map(affine, coefficients, message)
	}

	printOutput(message)
}

//	The callback function, shiftCipher, maps each alphabet
//	letter to n-steps in the english alphabet. The affine
//	cipher system is used as a helper for this cipher as they
//	relate to each other via the equation: E(x) = (key) mod26,
//	which mean that the second coefficient is the vertical
//	shift component of the function while the first can be seen
//	as the "period" likened to sine waves.
func shiftCipher(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	message := args["message"].Value
	key, _ := flags["key"].GetInt()
	coefficients := []int{0, key} //	y =  (key) mod 26

	var possibleOutputs []string
	switch flags["process"].Value {
	case "encrypt":
		possibleOutputs = append(possibleOutputs, Map(affine, coefficients, message))
	case "decrypt":
		//	missing shift key
		if key == 0 {
			for shift := 1; shift <= 25; shift++ {
				coefficients = []int{0, shift}
				possibleOutputs = append(possibleOutputs, Map(affine, coefficients, message))
			}
			possibleOutputs = filterGibberish(possibleOutputs)
			break
		}

		directions := []int{-1, 1}
		for _, dir := range directions {
			//	when shift key is provided
			coefficients = []int{0, key * dir}
			possibleOutputs = append(possibleOutputs, Map(affine, coefficients, message))
		}
		possibleOutputs = filterGibberish(possibleOutputs)
	}

	printOutput(possibleOutputs)
}

//	The callback function, vigenereCipher, maps each alphabet
//	letter according to a string key which maps each character
//	differently compared to the regular shift cipher.
func vigenereCipher(_ map[string]commando.ArgValue, _ map[string]commando.FlagValue) {

}

//	The callback function, railFenceCipher,
func railFenceCipher(_ map[string]commando.ArgValue, _ map[string]commando.FlagValue) {}

//	The callback function, rsaCipher,
func rsaCipher(_ map[string]commando.ArgValue, _ map[string]commando.FlagValue) {}
