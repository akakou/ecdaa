package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
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

/**
 * Hash some ECP2 values.
 *
 * Hash some ECP2 values with SHA256 algorism, and it returns a big integer.
 */
func HashECP2s(n ...*FP256BN.ECP2) *FP256BN.BIG {
	hasher := sha256.New()
	var buf [2*int(FP256BN.MODBYTES) + 1]byte

	for _, v := range n {
		v.ToBytes(buf[:], true)
		hasher.Write(buf[:])
	}

	retHash := hasher.Sum(nil)
	resBIG := FP256BN.FromBytes(retHash)

	resBIG.Mod(p())

	return resBIG
}

func HashFromBIGToECP(n *FP256BN.BIG) *FP256BN.ECP {
	fmt.Println("[CRETIGAL WARNING]This implemation of hash is not seccure!!!!!")

	g := g1()
	return g.Mul(n)
}

func HashToECP(message []byte) {
	var i uint32
	isOnCurve := false

	for ; i < 232 && !isOnCurve; i++ {
		// This process corresponds to BigNumberToB.
		// Compute BigNumberToB(i,4) on FIDO's spec indicated
		// that it should continue to find the number which
		// can be use for calculate the correct value on next step.
		numBuf := i32tob(i)

		hasher := sha256.New()
		hasher.Write(numBuf[:])
		hasher.Write(message[:])
		hash := hasher.Sum(nil)

		x := FP256BN.FromBytes(hash)

		z := x.Powmod(FP256BN.NewBIGint(3), p())
		z = x.Plus(b())
		z.Mod(p())

		y := FP256BN.Modsqr(z, p())
		ecp := FP256BN.NewECPbigs(x, y)

		isOnCurve = isOnECPCurve(ecp)

		fmt.Printf("y(%v): %v\n", isOnCurve, y)
	}
}

func i32tob(val uint32) []byte {
	r := make([]byte, 4)
	for i := uint32(0); i < 4; i++ {
		r[i] = byte((val >> (8 * i)) & 0xff)
	}
	return r
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

// func reverse(src []FP256BN.Chunk) []FP256BN.Chunk {
// 	dest := make([]FP256BN.Chunk, len(src))

// 	copy(dest, src)

// 	for i, j := 0, len(dest)-1; i < j; i, j = i+1, j-1 {
// 		dest[i], dest[j] = dest[j], dest[i]
// 	}

// 	return dest
// }
