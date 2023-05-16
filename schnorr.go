package ecdaa

import (
	"fmt"
	"miracl/core"
	"miracl/core/FP256BN"
)

var a Hash

type SchnorrProof struct {
	SmallC *FP256BN.BIG
	SmallS *FP256BN.BIG
	SmallN *FP256BN.BIG
	K      *FP256BN.ECP
}

type SchnorrProver struct{}

func commit(sk *FP256BN.BIG, B, S *FP256BN.ECP, rng *core.RAND, calcK bool) (*FP256BN.BIG, *FP256BN.ECP, *FP256BN.ECP, *FP256BN.ECP) {
	r := randomBig(rng)

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
	n := randomBig(rng)

	hash := newHash()
	hash.writeBIG(n, cDash)
	c := hash.sumToBIG()

	s := FP256BN.Modmul(c, sk, p())
	s = FP256BN.Modadd(r, s, p())

	return n, c, s
}

func proveSchnorr(message, basename []byte, sk *FP256BN.BIG, S, W *FP256BN.ECP, rng *core.RAND) *SchnorrProof {
	hash := newHash()
	hash.writeBytes(basename)
	B, _, _ := hash.hashToECP()

	r, E, L, K := commit(sk, B, S, rng, true)

	// c' = H(E, S, W, L, B, K, basename, message)
	hash = newHash()
	if basename == nil {
		hash.writeECP(E, S, W)
	} else {
		hash.writeECP(E, S, W, L, B, K)
	}

	hash.writeBytes(basename, message)
	a = hash

	cDash := hash.sumToBIG()

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
	hash := newHash()

	if basename == nil {
		hash.writeECP(E, S, W)
	} else {
		bHash := newHash()
		bHash.writeBytes(basename)

		B, _, err := bHash.hashToECP()
		if err != nil {
			return err
		}

		// L = B^s - K^c
		L := B.Mul(proof.SmallS)
		tmp = proof.K.Mul(proof.SmallC)
		L.Sub(tmp)

		hash.writeECP(E, S, W, L, B, proof.K)
	}

	hash.writeBytes(basename, message)
	cDash := hash.sumToBIG()

	// c = H( n | c' )
	cDashBuf := bigToBytes(cDash)

	hash = newHash()
	hash.writeBIG(proof.SmallN)
	hash.writeBytes(cDashBuf)

	c := hash.sumToBIG()

	if FP256BN.Comp(proof.SmallC, c) != 0 {
		return fmt.Errorf("c is not match: %v != %v", proof.SmallC, c)
	}

	return nil
}
