package ecdaa

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

func parseECPFromTPMFmt(tpmEcc *tpm2.TPMSECCPoint) *FP256BN.ECP {
	x := FP256BN.FromBytes(tpmEcc.X.Buffer)
	y := FP256BN.FromBytes(tpmEcc.Y.Buffer)

	return FP256BN.NewECPbigs(x, y)
}

func bigToBytes(big *FP256BN.BIG) []byte {
	var buf [FP256BN.MODBYTES]byte
	big.ToBytes(buf[:])
	return buf[:]
}

func randomBytes(rng *core.RAND, size int) []byte {
	rand := FP256BN.Random(rng)
	buf := bigToBytes(rand)
	return buf[:size]
}

func randomECP(rng *core.RAND) *FP256BN.ECP {
	r := randomBytes(rng, int(FP256BN.MODBYTES))
	return FP256BN.ECP_mapit(r)
}

func ecpToBytes(ecp *FP256BN.ECP) []byte {
	var buf [int(FP256BN.MODBYTES) + 1]byte
	ecp.ToBytes(buf[:], true)
	return buf[:]
}

func ecp2ToBytes(ecp2 *FP256BN.ECP2) []byte {
	var buf [2*int(FP256BN.MODBYTES) + 1]byte
	ecp2.ToBytes(buf[:], true)
	return buf[:]
}
