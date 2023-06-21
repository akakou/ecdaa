package ecdaa_bench

import (
	"miracl/core"
	"testing"

	"github.com/akakou/ecdaa"
)

func checkError(err error, t *testing.B) {
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func testIssuer(t *testing.B, rng *core.RAND) *ecdaa.Issuer {
	issuer := ecdaa.RandomIssuer(rng)

	err := ecdaa.VerifyIPK(&issuer.Ipk)

	if err != nil {
		t.Fatalf("%v", err)
	}

	return &issuer
}
