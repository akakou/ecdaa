package ecdaa_bench

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/akakou-fork/amcl-go/amcl/core"
	"github.com/akakou/ecdaa"
	"github.com/akakou/mcl_utils"
)

func setupSignatures(bsn []byte, signer ecdaa.Signer, rng *core.RAND, b *testing.B) []byte {
	signature, err := signer.Sign([]byte{}, bsn, rng)
	checkError(err, b)

	signatureBuf, err := signature.Encode()
	checkError(err, b)

	return signatureBuf
}

func benchmarkVerify(count int, b *testing.B) {
	rng := mcl_utils.InitRandom()

	var rl = ecdaa.RevocationList{}
	for i := 0; i < count; i++ {
		sk := mcl_utils.RandomBig(rng)
		rl = append(rl, sk)
	}

	bsn, err := hex.DecodeString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b98242cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7")
	checkError(err, b)

	issuer, signer, err := ecdaa.ExampleInitialize(rng)
	checkError(err, b)

	signatureBuf := setupSignatures(bsn, signer, rng, b)

	tag := fmt.Sprintf("verify-%v", count)

	var signature ecdaa.Signature
	signature.Decode(signatureBuf)

	b.Run(tag, func(b *testing.B) {
		for i := 0; i < b.N; i++ {

			err := ecdaa.Verify([]byte{}, bsn, &signature, &issuer.Ipk, rl)

			if err != nil {
				b.Fatalf("%v", err)
			}
		}
	})
}

func BenchmarkVerify(b *testing.B) {
	benchmarkVerify(0, b)

	for i := 1; i < 10000; i *= 10 {
		benchmarkVerify(i, b)
	}
}
