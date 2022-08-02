package main

import (
	"crypto/rand"
	"math/big"
	"miracl/core"
	"miracl/core/FP256BN"
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

func isOnECPCurve(point *FP256BN.ECP) bool {
	point.Affine()

	zero := FP256BN.NewBIGint(0)
	copied := FP256BN.NewECPbigs(zero, point.GetY())

	cofactor := FP256BN.NewBIGint(FP256BN.CURVE_Cof_I)
	unity := FP256BN.NewBIGint(1)

	if FP256BN.Comp(cofactor, unity) == 0 {
		return true
	}

	suspectedInf := copied.Mul(cofactor)

	if suspectedInf.Is_infinity() {
		return false
	}

	return true
}

func i32tob(val uint32) []byte {
	r := make([]byte, 4)
	for i := uint32(0); i < 4; i++ {
		r[i] = byte((val >> (8 * i)) & 0xff)
	}
	return r
}

// func reverse(src []FP256BN.Chunk) []FP256BN.Chunk {
// 	dest := make([]FP256BN.Chunk, len(src))

// 	copy(dest, src)

// 	for i, j := 0, len(dest)-1; i < j; i, j = i+1, j-1 {
// 		dest[i], dest[j] = dest[j], dest[i]
// 	}

// 	return dest
// }
