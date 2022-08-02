package main

import (
	"crypto/sha256"
	"fmt"
	"miracl/core/FP256BN"
)

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
