package tools

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/akakou-fork/amcl-go/miracl/core/FP256BN"

	amcl_utils "github.com/akakou/fp256bn-amcl-utils"
)

type Hash struct {
	B [][]byte
}

func NewHash() Hash {
	return Hash{}
}

func (h *Hash) WriteECP(n ...*FP256BN.ECP) {
	for _, v := range n {
		buf := amcl_utils.EcpToBytes(v)
		h.B = append(h.B, buf)
	}
}

func (h *Hash) WriteECP2(n ...*FP256BN.ECP2) {
	for _, v := range n {
		buf := amcl_utils.Ecp2ToBytes(v)
		h.B = append(h.B, buf[:])
	}
}

func (h *Hash) WriteBIG(n ...*FP256BN.BIG) {
	for _, v := range n {
		buf := amcl_utils.BigToBytes(v)
		h.B = append(h.B, buf)
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
	resBIG.Mod(amcl_utils.P())

	return resBIG
}

func (baseHash *Hash) HashToECP() (*FP256BN.ECP, uint32, error) {
	var i uint32

	base := baseHash.B

	for i = 0; i <= 232; i++ {
		hash := NewHash()
		// This process corresponds to BigNumberToB.
		// Compute BigNumberToB(i,4) on FIDO's spec indicated
		// that it should continue to find the number which
		// can be use for calculate the correct value on next step.
		numBuf := make([]byte, binary.MaxVarintLen32)
		binary.PutVarint(numBuf, int64(i))

		hash.B = append([][]byte{numBuf}, base...)

		x := hash.SumToBIG()

		ecp := FP256BN.NewECPbig(x)
		ecp = ecp.Mul(FP256BN.NewBIGint(FP256BN.CURVE_Cof_I))

		if !ecp.Is_infinity() {
			return ecp, i, nil
		}
	}

	return nil, 0, fmt.Errorf("error: Hashing failed")
}

func DiffHash(a Hash, b Hash) error {
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
		return nil
	} else {
		return fmt.Errorf(result)
	}
}
