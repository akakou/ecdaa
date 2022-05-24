package main

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"golang.org/x/crypto/bn256"
)

func main() {
	isk, err := RandomISK()

	if err != nil {
		println("error random isk")
	}

	_, err = RandomIPK(isk)

	if err != nil {
		println("error random ipk")
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
	X   *bn256.G2
	Y   *bn256.G2
	c   *big.Int
	s_x *big.Int
	s_y *big.Int
}

type Issuer struct {
	ipk IPK
	isk ISK
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

func RandomIPK(isk *ISK) (*IPK, error) {
	// random r_x, r_y
	ipk := new(IPK)

	r_x, err := rand.Int(rand.Reader, order)

	if err != nil {
		return nil, err
	}

	r_y, err := rand.Int(rand.Reader, order)

	if err != nil {
		return nil, err
	}

	// calc X, Y, U_x, U_y
	X := new(bn256.G2).ScalarBaseMult(isk.x)
	Y := new(bn256.G2).ScalarBaseMult(isk.y)

	U_x := new(bn256.G2).ScalarBaseMult(r_x)
	U_y := new(bn256.G2).ScalarBaseMult(r_y)

	// calc `c = H(U_x | U_y | X | Y)`
	h := sha256.New()
	h.Write(U_x.Marshal())
	h.Write(U_y.Marshal())
	h.Write(X.Marshal())
	h.Write(Y.Marshal())
	bufC := h.Sum(nil)

	c := new(big.Int).SetBytes(bufC)

	// calc s_x, s_y
	//     s_x = r_x + cx
	//     s_y = r_y + cy
	// todo: mod p
	s_x := new(big.Int)
	s_x.Mul(c, isk.x)
	s_x.Add(s_x, r_x)

	s_y := new(big.Int)
	s_y.Mul(c, isk.y)
	s_y.Add(s_y, r_y)

	// copy pointers to ipk
	ipk.X = X
	ipk.Y = Y
	ipk.c = c
	ipk.s_x = s_x
	ipk.s_y = s_y

	return ipk, nil
}

