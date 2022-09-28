package ecdaa

import (
	"miracl/core"
	"testing"
)

func TestIPKEncodeDecode(t *testing.T) {
	isk := RandomISK(core.NewRAND())
	ipk := RandomIPK(&isk, core.NewRAND())

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
	cred.A = randomECP(core.NewRAND())
	cred.B = randomECP(core.NewRAND())
	cred.C = randomECP(core.NewRAND())
	cred.D = randomECP(core.NewRAND())

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
