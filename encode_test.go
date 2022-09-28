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
