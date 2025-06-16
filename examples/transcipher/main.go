package main

import (
	"flag"
	"runtime"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/ckks_cipher"
)



func main() {

	runtime.GOMAXPROCS(64)
	// Default LogN, which with the following defined parameters
	// provides a security of 128-bit.
    mode := flag.String("mode", "test", "set mode: test or benchmark")

    flag.Parse()
	flag_mode := -1
    // verify the mode input
    switch *mode {
    case "test":
		flag_mode = 0
        fmt.Println("Running in test mode")
    case "benchmark":
		flag_mode = 1
        fmt.Println("Running in benchmark mode")
    default:
        fmt.Printf("Unknown mode: %s\n", *mode)
        fmt.Println("Please use --mode=test or --mode=benchmark")
		panic("Running error occurred! Check the input parameter! ")
    }

	// ckks_cipher.RastaParam14()
	ckks_cipher.AESParam14(flag_mode)
	// ckks_cipher.AESParam13()
}

// 579 with logN=16