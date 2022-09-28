package ecdaa

import (
	"miracl/core"
	"miracl/core/FP256BN"
	"testing"
)

func TestIPKEncodeDecode(t *testing.T) {
	rnd := core.NewRAND()

	isk := RandomISK(rnd)
	ipk := RandomIPK(&isk, rnd)

	encoded := ipk.Encode()
	decoded := encoded.Decode()

	if !ipk.X.Equals(decoded.X) {
		t.Fatalf("X is not equal")
	}

	if !ipk.Y.Equals(decoded.Y) {
		t.Fatalf("Y is not equal")
	}

	if ipk.C.ToString() != decoded.C.ToString() {
		t.Fatalf("C is not equal")
	}

	if ipk.SX.ToString() != decoded.SX.ToString() {
		t.Fatalf("SX is not equal")
	}

	if ipk.SY.ToString() != decoded.SY.ToString() {
		t.Fatalf("SY is not equal")
	}
}

func TestISKEncodeDecode(t *testing.T) {
	isk := RandomISK(core.NewRAND())

	encoded := isk.Encode()
	decoded := encoded.Decode()

	if isk.X.ToString() != decoded.X.ToString() {
		t.Fatalf("X is not equal")
	}

	if isk.Y.ToString() != decoded.Y.ToString() {
		t.Fatalf("Y is not equal")
	}
}

func TestCredentialEncodeDecode(t *testing.T) {
	var cred Credential

	rnd := core.NewRAND()

	cred.A = randomECP(rnd)
	cred.B = randomECP(rnd)
	cred.C = randomECP(rnd)
	cred.D = randomECP(rnd)

	encoded := cred.Encode()
	decoded := encoded.Decode()

	if !cred.A.Equals(decoded.A) {
		t.Fatalf("A is not equal")
	}

	if !cred.B.Equals(decoded.B) {
		t.Fatalf("B is not equal")
	}

	if !cred.C.Equals(decoded.C) {
		t.Fatalf("C is not equal")
	}

	if !cred.D.Equals(decoded.D) {
		t.Fatalf("D is not equal")
	}
}

func TestSignatureEncode(t *testing.T) {
	var signature Signature

	rnd := core.NewRAND()

	signature.C = FP256BN.Random(rnd)
	signature.C2 = FP256BN.Random(rnd)
	signature.N = FP256BN.Random(rnd)
	signature.SmallS = FP256BN.Random(rnd)

	signature.R = randomECP(rnd)
	signature.S = randomECP(rnd)
	signature.T = randomECP(rnd)
	signature.W = randomECP(rnd)
	signature.E = randomECP(rnd)
	signature.K = randomECP(rnd)

	encoded := signature.Encode()
	decoded := encoded.Decode()

	if FP256BN.Comp(signature.C, decoded.C) != 0 {
		t.Fatalf("C is not equal")
	}

	if FP256BN.Comp(signature.C2, decoded.C2) != 0 {
		t.Fatalf("C2 is not equal")
	}

	if FP256BN.Comp(signature.N, decoded.N) != 0 {
		t.Fatalf("N is not equal")
	}

	if FP256BN.Comp(signature.SmallS, decoded.SmallS) != 0 {
		t.Fatalf("SmallS is not equal")
	}

	if !signature.R.Equals(decoded.R) {
		t.Fatalf("R is not equal")
	}

	if !signature.S.Equals(decoded.S) {
		t.Fatalf("S is not equal")
	}

	if !signature.T.Equals(decoded.T) {
		t.Fatalf("T is not equal")
	}

	if !signature.W.Equals(decoded.W) {
		t.Fatalf("W is not equal")
	}

	if !signature.E.Equals(decoded.E) {
		t.Fatalf("E is not equal")
	}

	if !signature.K.Equals(decoded.K) {
		t.Fatalf("K is not equal")
	}
}
