package ecdaa

import (
	"fmt"

	"github.com/akakou-fork/amcl-go/miracl/core"

	"github.com/akakou-fork/amcl-go/miracl/core/FP256BN"

	"github.com/akakou/mcl_utils"

	"github.com/akakou/ecdaa/tools"
)

type SchnorrProof struct {
	SmallC *FP256BN.BIG
	SmallS *FP256BN.BIG
	SmallN *FP256BN.BIG
	K      *FP256BN.ECP
}

type SchnorrProver struct{}

func commit(sk *FP256BN.BIG, B, S *FP256BN.ECP, rng *core.RAND, calcK bool) (*FP256BN.BIG, *FP256BN.ECP, *FP256BN.ECP, *FP256BN.ECP) {
	r := mcl_utils.RandomBig(rng)

	E := S.Mul(r)
	L := B.Mul(r)

	var K *FP256BN.ECP
	if calcK {
		K = B.Mul(sk)
	} else {
		K = nil
	}

	return r, E, L, K
}

func sign(r, cDash, sk *FP256BN.BIG, rng *core.RAND) (*FP256BN.BIG, *FP256BN.BIG, *FP256BN.BIG) {
	n := mcl_utils.RandomBig(rng)

	hash := tools.NewHash()
	hash.WriteBIG(n, cDash)
	c := hash.SumToBIG()

	s := FP256BN.Modmul(c, sk, mcl_utils.P())
	s = FP256BN.Modadd(r, s, mcl_utils.P())

	return n, c, s
}

func proveSchnorr(message, basename []byte, sk *FP256BN.BIG, S, W *FP256BN.ECP, rng *core.RAND) *SchnorrProof {
	hash := tools.NewHash()
	hash.WriteBytes(basename)
	B, _, _ := hash.HashToECP()

	r, E, L, K := commit(sk, B, S, rng, true)

	// c' = H(E, S, W, L, B, K, basename, message)
	hash = tools.NewHash()
	if basename == nil {
		hash.WriteECP(E, S, W)
	} else {
		hash.WriteECP(E, S, W, L, B, K)
	}

	hash.WriteBytes(basename, message)

	cDash := hash.SumToBIG()

	n, c, s := sign(r, cDash, sk, rng)

	return &SchnorrProof{
		SmallC: c,
		SmallS: s,
		SmallN: n,
		K:      K,
	}
}

func verifySchnorr(message, basename []byte, proof *SchnorrProof, S, W *FP256BN.ECP) error {
	// E = S^s W ^ (-c)
	E := S.Mul(proof.SmallS)
	tmp := W.Mul(proof.SmallC)
	E.Sub(tmp)

	// c' = H(E, S, W, L, B, K, basename, message)
	hash := tools.NewHash()

	if basename == nil {
		hash.WriteECP(E, S, W)
	} else {
		bHash := tools.NewHash()
		bHash.WriteBytes(basename)

		B, _, err := bHash.HashToECP()
		if err != nil {
			return err
		}

		// L = B^s - K^c
		L := B.Mul(proof.SmallS)
		tmp = proof.K.Mul(proof.SmallC)
		L.Sub(tmp)

		hash.WriteECP(E, S, W, L, B, proof.K)
	}

	hash.WriteBytes(basename, message)
	cDash := hash.SumToBIG()

	// c = H( n | c' )
	cDashBuf := mcl_utils.BigToBytes(cDash)

	hash = tools.NewHash()
	hash.WriteBIG(proof.SmallN)
	hash.WriteBytes(cDashBuf)

	c := hash.SumToBIG()

	if FP256BN.Comp(proof.SmallC, c) != 0 {
		return fmt.Errorf("c is not match: %v != %v", proof.SmallC, c)
	}

	return nil
}
