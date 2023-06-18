package ecdaa

import (
	"mcl_utils"
	"testing"
)

func TestNewIssuer(t *testing.T) {
	rng := mcl_utils.InitRandom()

	issuer := RandomIssuer(rng)

	err := VerifyIPK(&issuer.Ipk)

	if err != nil {
		t.Fatalf("%v", err)
	}
}
