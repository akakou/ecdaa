package ecdaa_bench

import (
	"testing"

	"github.com/akakou-fork/amcl-go/miracl/core/FP256BN"
	_acml "github.com/akakou/fp256bn-amcl-utils"

	"github.com/akakou/ecdaa/tools"
)

func BenchmarkPrimitive(b *testing.B) {
	g1 := _acml.G1()
	g2 := _acml.G2()
	rnd := _acml.InitRandom()
	r := _acml.RandomBig(rnd)

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
			_acml.InitRandom()
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
