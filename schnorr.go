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

func commit(sk *FP256BN.BIG, S, W *FP256BN.ECP, rng *core.RAND) (*FP256BN.BIG, *FP256BN.ECP, *FP256BN.ECP, *FP256BN.ECP) {
	r := randomBig(rng)

	E := S.Mul(r)
	L := W.Mul(r)
	K := S.Mul(sk)

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

	r, E, L, K := commit(sk, S, W, rng)

	// c' = H(E, S, W, L, B, K, basename, message)
	hash = newHash()
	hash.writeECP(E, S, L, B, K)
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
	hash := newHash()
	hash.writeBytes(basename)
	B, _, err := hash.hashToECP()
	if err != nil {
		return err
	}

	// E = S ^ s
	E := FP256BN.NewECP()
	E.Copy(S)
	E = E.Mul(proof.SmallS)

	// E = W ^ c
	tmp2 := FP256BN.NewECP()
	tmp2.Copy(W)
	tmp2 = tmp2.Mul(proof.SmallC)

	// E = S^s W ^ (-c)
	E.Sub(tmp2)

	// L = P2 ^ s
	L := B.Mul(proof.SmallS)

	// c * K
	tmp3 := proof.K.Mul(proof.SmallC)
	L.Sub(tmp3)

	// c' = H(E, S, W, L, B, K, basename, message)
	hash = newHash()
	hash.writeECP(E, S, L, B, proof.K)
	hash.writeBytes(basename, message)

	fmt.Printf("%v", diffHash(hash, a))
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
