package main

import (
	"crypto/rand"
	"math/big"
	"miracl/core"
	"miracl/core/FP256BN"

	"github.com/google/go-tpm/tpm2"
)

/**
 * Initialize random.
 */
func InitRandom() *core.RAND {
	var seed [SEED_SIZE]byte
	rng := core.NewRAND()

	for i := 0; i < SEED_SIZE; i++ {
		s, _ := rand.Int(rand.Reader, big.NewInt(256))
		seed[i] = byte(s.Int64())
	}

	rng.Seed(SEED_SIZE, seed[:])

	return rng
}

func ParseECPFromTPMFmt(tpmEcc *tpm2.TPMSECCPoint) *FP256BN.ECP {
	x := FP256BN.FromBytes(tpmEcc.X.Buffer)
	y := FP256BN.FromBytes(tpmEcc.Y.Buffer)

	return FP256BN.NewECPbigs(x, y)
}

func ParseECP2FromTPMFmt(tpmEcc *tpm2.TPMSECCPoint) *FP256BN.ECP2 {
	big_x := FP256BN.FromBytes(tpmEcc.X.Buffer)
	big_y := FP256BN.FromBytes(tpmEcc.Y.Buffer)

	fp_x := FP256BN.NewFP2big(big_x)
	fp_y := FP256BN.NewFP2big(big_y)

	return FP256BN.NewECP2fp2s(fp_x, fp_y)
}
