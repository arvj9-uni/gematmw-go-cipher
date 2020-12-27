package main

import (
	"fmt"

	"github.com/thatisuday/commando"
)

func main() {
	fmt.Println("Hello World")
	commando.
		SetExecutableName("cipher").
		SetVersion("1.0.0").
		SetDescription("This CLI application allows one to encrypt and decrypt messages.")
}
