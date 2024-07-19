package ecdaa

import (
	"testing"

	_acml "github.com/akakou/fp256bn-amcl-utils"
)

func TestNewIssuer(t *testing.T) {
	rng := _acml.InitRandom()

	issuer := RandomIssuer(rng)

	err := VerifyIPK(&issuer.Ipk)

	if err != nil {
		t.Fatalf("%v", err)
	}
}
