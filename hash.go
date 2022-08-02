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

func HashToECP(m *FP256BN.BIG) (*FP256BN.ECP, error) {
	var ecp *FP256BN.ECP

	var buf [FP256BN.MODBYTES]byte
	m.ToBytes(buf[:])

	var i uint32
	for i = 0; i <= 232; i++ {
		// This process corresponds to BigNumberToB.
		// Compute BigNumberToB(i,4) on FIDO's spec indicated
		// that it should continue to find the number which
		// can be use for calculate the correct value on next step.
		numBuf := i32tob(i)

		hasher := sha256.New()
		hasher.Write(numBuf[:])
		hasher.Write(buf[:])
		hash := hasher.Sum(nil)

		x := FP256BN.FromBytes(hash)
		x.Mod(p())

		ecp = FP256BN.NewECPbig(x)

		if !ecp.Is_infinity() {
			return ecp, nil
		}
	}

	return nil, fmt.Errorf("error: Hashing failed")
}
