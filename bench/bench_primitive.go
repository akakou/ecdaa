package ecdaa_bench

import (
	"miracl/core/FP256BN"
	"testing"

	"github.com/akakou/ecdaa/tools"
	"github.com/akakou/mcl_utils"
)

func BenchmarkPrimitive(b *testing.B) {
	g1 := mcl_utils.G1()
	g2 := mcl_utils.G2()
	rnd := mcl_utils.InitRandom()
	r := mcl_utils.RandomBig(rnd)

	b.Run("mult g1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			g1.Mul(r)
		}
	})

	b.Run("mult g2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			g2.Mul(r)
		}
	})

	b.Run("pairing", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			FP256BN.Ate(g2, g1)
		}
	})

	b.Run("init random", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			mcl_utils.InitRandom()
		}
	})

	b.Run("add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			g1.Add(g1)
		}
	})

	b.Run("sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			g1.Sub(g1)
		}
	})

	b.Run("hash to ecp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			hash := tools.NewHash()
			hash.WriteECP(g1, g1, g1, g1, g1, g1)
			hash.SumToBIG()
		}
	})

	b.Run("hash to big", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			hash := tools.NewHash()
			hash.WriteECP(g1, g1, g1, g1, g1, g1)
			hash.HashToECP()
		}
	})
}
