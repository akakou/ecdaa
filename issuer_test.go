package ecdaa

import (
	"testing"

	"github.com/anonymous/mcl_utils"
)

func TestNewIssuer(t *testing.T) {
	rng := mcl_utils.InitRandom()

	issuer := RandomIssuer(rng)

	err := VerifyIPK(&issuer.Ipk)

	if err != nil {
		t.Fatalf("%v", err)
	}
}
