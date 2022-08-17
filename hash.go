package main

import (
	"crypto/sha256"
	"encoding/binary"
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

func HashToECP(m []byte) (*FP256BN.ECP, uint32, error) {
	var ecp *FP256BN.ECP

	var i uint32
	for i = 0; i <= 232; i++ {
		// This process corresponds to BigNumberToB.
		// Compute BigNumberToB(i,4) on FIDO's spec indicated
		// that it should continue to find the number which
		// can be use for calculate the correct value on next step.
		numBuf := make([]byte, binary.MaxVarintLen32)
		binary.PutVarint(numBuf, int64(i))

		//  x = H(numBuf | m)
		hasher := sha256.New()
		hasher.Write(numBuf[:])
		hasher.Write(m[:])
		hash := hasher.Sum(nil)

		x := FP256BN.FromBytes(hash)
		x.Mod(p())

		ecp = FP256BN.NewECPbig(x)
		ecp = ecp.Mul(FP256BN.NewBIGint(FP256BN.CURVE_Cof_I))

		if !ecp.Is_infinity() {
			return ecp, i, nil
		}
	}

	return nil, 0, fmt.Errorf("error: Hashing failed")
}
