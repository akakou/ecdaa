package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"miracl/core/FP256BN"
)

type Hash struct {
	B [][]byte
}

func NewHash() Hash {
	return Hash{}
}

func (h *Hash) WriteECP(n ...*FP256BN.ECP) {
	var buf [int(FP256BN.MODBYTES)]byte

	for _, v := range n {
		v.ToBytes(buf[:], true)
		h.B = append(h.B, buf[:])
	}
}

func (h *Hash) WriteECP2(n ...*FP256BN.ECP2) {
	var buf [2*int(FP256BN.MODBYTES) + 1]byte

	for _, v := range n {
		v.ToBytes(buf[:], true)
		h.B = append(h.B, buf[:])
	}
}

func (h *Hash) WriteBIG(n ...*FP256BN.BIG) {
	var buf [int(FP256BN.MODBYTES)]byte

	for _, v := range n {
		v.ToBytes(buf[:])
		h.B = append(h.B, buf[:])
	}
}

func (h *Hash) WriteBytes(n ...[]byte) {
	for _, v := range n {
		h.B = append(h.B, v)
	}
}

func (h *Hash) SumToBytes() []byte {
	hash := sha256.New()

	for _, v := range h.B {
		hash.Write(v)
	}

	retHash := hash.Sum(nil)
	return retHash
}

func (h *Hash) SumToBIG() *FP256BN.BIG {
	retHash := h.SumToBytes()
	resBIG := FP256BN.FromBytes(retHash)
	resBIG.Mod(p())

	return resBIG
}

func (h *Hash) HashToECP() (*FP256BN.ECP, uint32, error) {
	var i uint32
	for i = 0; i <= 232; i++ {
		// This process corresponds to BigNumberToB.
		// Compute BigNumberToB(i,4) on FIDO's spec indicated
		// that it should continue to find the number which
		// can be use for calculate the correct value on next step.
		numBuf := make([]byte, binary.MaxVarintLen32)
		binary.PutVarint(numBuf, int64(i))

		h.B = append([][]byte{numBuf}, h.B...)

		x := h.SumToBIG()

		ecp := FP256BN.NewECPbig(x)
		ecp = ecp.Mul(FP256BN.NewBIGint(FP256BN.CURVE_Cof_I))

		if !ecp.Is_infinity() {
			return ecp, i, nil
		}
	}

	return nil, 0, fmt.Errorf("error: Hashing failed")
}
