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

// func reverse(src []FP256BN.Chunk) []FP256BN.Chunk {
// 	dest := make([]FP256BN.Chunk, len(src))

// 	copy(dest, src)

// 	for i, j := 0, len(dest)-1; i < j; i, j = i+1, j-1 {
// 		dest[i], dest[j] = dest[j], dest[i]
// 	}

// 	return dest
// }
