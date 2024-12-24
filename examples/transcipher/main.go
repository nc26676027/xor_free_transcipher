package main

import (
	"flag"
	"runtime"

	"github.com/tuneinsight/lattigo/v6/ckks_cipher"
)



func main() {

	flag.Parse()
	runtime.GOMAXPROCS(32)
	// Default LogN, which with the following defined parameters
	// provides a security of 128-bit.
	ckks_cipher.AESParam14()
}

// 579 with logN=16