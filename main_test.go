package main

import (
	"testing"
)

func TestAll(t *testing.T) {
	rng := InitRandom()

	issuer := RandomIssuer(rng)

	err := VerifyIPK(&issuer.ipk)
	if err != nil {
		t.Errorf("error: %v", err)
	}
}
