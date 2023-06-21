package ecdaa_bench

import (
	"encoding/hex"
	"fmt"
	"miracl/core"
	"testing"

	"github.com/akakou/ecdaa"
	"github.com/akakou/mcl_utils"
)

func setupSWSigner(rng *core.RAND, b *testing.B) (*ecdaa.SWSigner, *ecdaa.IPK) {
	issuer := testIssuer(b, rng)

	seed, issuerB, err := ecdaa.GenJoinSeed(rng)
	checkError(err, b)

	req, sk, err := ecdaa.GenJoinReq(seed, rng)
	checkError(err, b)

	cred, err := issuer.MakeCred(req, issuerB, rng)
	checkError(err, b)

	signer := ecdaa.NewSWSigner(cred, sk)

	return &signer, &issuer.Ipk
}

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

	bsn, err := hex.DecodeString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
	checkError(err, b)

	signer, ipk := setupSWSigner(rng, b)
	signatureBuf := setupSignatures(bsn, signer, rng, b)

	tag := fmt.Sprintf("verify-%v", count)

	b.Run(tag, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var signature ecdaa.Signature

			signature.Decode(signatureBuf)
			err := ecdaa.Verify([]byte{}, bsn, &signature, ipk, rl)

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
