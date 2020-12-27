package main

import (
	"fmt"

	"github.com/thatisuday/commando"
)

func shiftCipher(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	fmt.Printf("Printing options of the `root` command...\n\n")

	// print arguments
	for k, v := range args {
		fmt.Printf("arg -> %v: %v(%T)\n", k, v.Value, v.Value)
	}

	// print flags
	for k, v := range flags {
		fmt.Printf("flag -> %v: %v(%T)\n", k, v.Value, v.Value)
	}
}

func main() {
	fmt.Println("Hello World")
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
