package ecdaa

import (
	"testing"

	amcl_utils "github.com/akakou/fp256bn-amcl-utils"
)

func TestNewIssuer(t *testing.T) {
	rng := amcl_utils.InitRandom()

	issuer := RandomIssuer(rng)

	err := VerifyIPK(&issuer.Ipk)

	if err != nil {
		t.Fatalf("%v", err)
	}
}
