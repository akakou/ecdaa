package ecdaa

import (
	"fmt"
	"miracl/core"
	"miracl/core/FP256BN"

	"github.com/google/go-tpm/tpm2"
)

type RevocationList = []*FP256BN.BIG

type Member struct {
	Tpm        *TPM
	KeyHandles *KeyHandles
}

type KeyHandles struct {
	EkHandle  *tpm2.AuthHandle
	SrkHandle *tpm2.NamedHandle
	Handle    *tpm2.AuthHandle
}

func NewMember(tpm *TPM) Member {
	var member = Member{
		Tpm: tpm,
	}

	return member
}

type Signature struct {
	Proof          *SchnorrProof
	RandomizedCred *Credential
}

func Sign(
	message,
	basename []byte,
	sk *FP256BN.BIG, cred *Credential,
	rng *core.RAND) (*Signature, error) {

	randomizedCred := RandomizeCred(cred, rng)
	proof := proveSchnorr(message, basename, sk, randomizedCred.B, randomizedCred.D, rng)

	return &Signature{
		Proof:          proof,
		RandomizedCred: randomizedCred,
	}, nil
}

func Verify(message, basename []byte, signature *Signature, ipk *IPK, rl RevocationList) error {
	err := verifySchnorr(message, basename, signature.Proof, signature.RandomizedCred.B, signature.RandomizedCred.D)

	if err != nil {
		return err
	}

	err = VerifyCred(signature.RandomizedCred, ipk)
	if err != nil {
		return err
	}

	for _, revoked := range rl {
		tmp4 := FP256BN.NewECP()
		tmp4.Copy(signature.RandomizedCred.B)
		tmp4 = tmp4.Mul(revoked)

		if signature.RandomizedCred.D.Equals(tmp4) {
			return fmt.Errorf("the secret key revoked")
		}
	}

	return nil
}

//   // E = S^s . W^-c
//     // ----------------
//     // S^s . W^-c
//     //     = S^(r + c . sk) . W^-c
//     //     = S^(r + c . sk) . W^-(c)
//     //     = B^l .(r + c . sk) . Q^-(c . r . l)
//     //     = B  .(r + c . sk) . Q ^ - (c . r )
//     //     = B ^ sk
//     let mut e = s.mul(&self.s);
//     let tmp = w.mul(&self.c);
//     e.sub(&tmp);

//     // L = B^s - K^c
//     // ----------
//     // B^s - K^c
//     //     = B^(r + c . sk) - B^(c . sk)
//     //     = B^r
//     //     = L
//     let mut l = hash.mul(&self.s);
//     let tmp = self.k.mul(&self.c);
//     l.sub(&tmp);
