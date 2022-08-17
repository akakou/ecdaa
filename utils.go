package main

import (
	"crypto/rand"
	"math/big"
	"miracl/core"
)

/**
 * Initialize random.
 */
func InitRandom() *core.RAND {
	var seed [SEED_SIZE]byte
	rng := core.NewRAND()

	for i := 0; i < SEED_SIZE; i++ {
		s, _ := rand.Int(rand.Reader, big.NewInt(256))
		seed[i] = byte(s.Int64())
	}

	rng.Seed(SEED_SIZE, seed[:])

	return rng
}
