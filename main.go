package main

import (
	"crypto/rand"
	"math/big"

	"golang.org/x/crypto/bn256"
)

func main() {
	_, err := RandomISK()

	if err != nil {
		println("err!")
	}

	println("ok!")

}

func Order() *big.Int {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(256), nil).Sub(max, big.NewInt(1))

	return max
}

var order = Order()

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

func RandomISK() (*ISK, error) {
	isk := new(ISK)

	x, err := rand.Int(rand.Reader, order)

	if err != nil {
		return nil, err
	}

	y, err := rand.Int(rand.Reader, order)

	if err != nil {
		return nil, err
	}

	isk.x = x
	isk.y = y

	return isk, nil
}
