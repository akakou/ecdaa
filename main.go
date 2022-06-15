package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"miracl/core"
	"miracl/core/FP256BN"
)

const SEED_SIZE = 100

type ISK struct {
	x *FP256BN.BIG
	y *FP256BN.BIG
}

func RandomISK(rng *core.RAND) ISK {
	var isk ISK
	x := FP256BN.Random(rng)
	y := FP256BN.Random(rng)

	isk.x = x
	isk.y = y

	return isk
}

func main() {
	var seed [SEED_SIZE]byte
	rng := core.NewRAND()

	for i := 0; i < SEED_SIZE; i++ {
		s, _ := rand.Int(rand.Reader, big.NewInt(256))
		seed[i] = byte(s.Int64())
	}

	rng.Seed(SEED_SIZE, seed[:])

	isk := RandomISK(rng)

	fmt.Println("x: %v", isk.x)
	fmt.Println("y: %v", isk.y)
}
