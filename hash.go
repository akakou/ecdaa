package ecdaa

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"miracl/core/FP256BN"
	"reflect"
)

type Hash struct {
	B [][]byte
}

func newHash() Hash {
	return Hash{}
}

func (h *Hash) writeECP(n ...*FP256BN.ECP) {
	for _, v := range n {
		buf := ecpToBytes(v)
		h.B = append(h.B, buf)
	}
}

func (h *Hash) writeECP2(n ...*FP256BN.ECP2) {
	for _, v := range n {
		buf := ecp2ToBytes(v)
		h.B = append(h.B, buf[:])
	}
}

func (h *Hash) writeBIG(n ...*FP256BN.BIG) {
	for _, v := range n {
		buf := bigToBytes(v)
		h.B = append(h.B, buf)
	}
}

func (h *Hash) writeBytes(n ...[]byte) {
	for _, v := range n {
		h.B = append(h.B, v)
	}
}

func (h *Hash) sumToBytes() []byte {
	hash := sha256.New()

	for _, v := range h.B {
		hash.Write(v)
	}

	retHash := hash.Sum(nil)
	return retHash
}

func (h *Hash) sumToBIG() *FP256BN.BIG {
	retHash := h.sumToBytes()
	resBIG := FP256BN.FromBytes(retHash)
	resBIG.Mod(p())

	return resBIG
}

func (baseHash *Hash) hashToECP() (*FP256BN.ECP, uint32, error) {
	var i uint32

	base := baseHash.B

	for i = 0; i <= 232; i++ {
		hash := newHash()
		// This process corresponds to BigNumberToB.
		// Compute BigNumberToB(i,4) on FIDO's spec indicated
		// that it should continue to find the number which
		// can be use for calculate the correct value on next step.
		numBuf := make([]byte, binary.MaxVarintLen32)
		binary.PutVarint(numBuf, int64(i))

		hash.B = append([][]byte{numBuf}, base...)

		x := hash.sumToBIG()

		ecp := FP256BN.NewECPbig(x)
		ecp = ecp.Mul(FP256BN.NewBIGint(FP256BN.CURVE_Cof_I))

		if !ecp.Is_infinity() {
			return ecp, i, nil
		}
	}

	return nil, 0, fmt.Errorf("error: Hashing failed")
}

func diffHash(a Hash, b Hash) {
	result := ""

	if len(a.B) != len(b.B) {
		result += fmt.Sprintf("size not match %v != %v\n", len(a.B), len(b.B))
	}

	for i := range a.B {
		if !reflect.DeepEqual(a.B[i], b.B[i]) {
			result = fmt.Sprintf("%v\nnot match (%v) %v != %v\n", result, i, a.B[i], b.B[i])
		}
	}

	if result == "" {
		fmt.Println("diff: ok")
	} else {
		fmt.Printf("diff: %v\n", result)
	}
}
