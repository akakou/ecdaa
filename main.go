package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"golang.org/x/crypto/bn256"
)

func main() {
	fmt.Printf("Hello World\n")
}



type ISK struct {
	x *big.Int
	y *big.Int
}

type IPK struct {
	X   bn256.G2
	Y   bn256.G2
	c   big.Int
	s_x big.Int
	s_y big.Int
}

type Issuer struct {
	ipk *IPK
	isk *ISK
}

