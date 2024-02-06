package mcl_utils

import (
	"crypto/rand"
	"math/big"

	"github.com/akakou-fork/amcl-go/miracl/core"
	"github.com/akakou-fork/amcl-go/miracl/core/FP256BN"
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

func BigToBytes(big *FP256BN.BIG) []byte {
	var buf [FP256BN.MODBYTES]byte
	big.ToBytes(buf[:])
	return buf[:]
}

func RandomBig(rng *core.RAND) *FP256BN.BIG {
	rand := FP256BN.Random(rng)

	buf := BigToBytes(rand)
	big := FP256BN.FromBytes(buf)

	return big
}

func RandomBytes(rng *core.RAND, size int) []byte {
	rand := FP256BN.Random(rng)
	buf := BigToBytes(rand)
	return buf[:size]
}

func RandomECP(rng *core.RAND) *FP256BN.ECP {
	r := RandomBytes(rng, int(FP256BN.MODBYTES))
	return FP256BN.ECP_mapit(r)
}

func EcpToBytes(ecp *FP256BN.ECP) []byte {
	var buf [int(FP256BN.MODBYTES) + 1]byte
	ecp.ToBytes(buf[:], true)
	return buf[:]
}

func Ecp2ToBytes(ecp2 *FP256BN.ECP2) []byte {
	var buf [2*int(FP256BN.MODBYTES) + 1]byte
	ecp2.ToBytes(buf[:], true)
	return buf[:]
}
