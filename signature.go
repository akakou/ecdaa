package ecdaa

import (
	"encoding/binary"
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
	proof, err := proveSchnorr(message, basename, sk, nil, randomizedCred.B, randomizedCred.D, rng)

	if err != nil {
		return nil, err
	}

	return &Signature{
		Proof:          proof,
		RandomizedCred: randomizedCred,
	}, nil
}

func SignTPM(message, basename []byte, cred *Credential, handle *KeyHandles, tpm *TPM, rng *core.RAND) (*Signature, error) {
	hash := newHash()
	hash.writeBytes(basename)

	B, i, err := hash.hashToECP()

	if err != nil {
		return nil, err
	}

	numBuf := make([]byte, binary.MaxVarintLen32)
	binary.PutVarint(numBuf, int64(i))

	s2Buf := append(numBuf, basename[:]...)

	randomizedCred := RandomizeCred(cred, rng)
	S := randomizedCred.B
	W := randomizedCred.D

	/* run commit and get U */
	comRsp, E, L, K, err := (*tpm).Commit(handle.Handle, S, s2Buf, B)

	if err != nil {
		return nil, fmt.Errorf("commit error: %v\n", err)
	}

	// c2 = H(E, S, W, L, B, K,basename, message)
	hash = newHash()
	hash.writeECP(E, S, W, L, B, K)
	hash.writeBytes(basename, message)

	c2 := hash.sumToBIG()

	/* sign and get s1, n */
	c2Buf := bigToBytes(c2)

	_, s, n, err := (*tpm).Sign(c2Buf, comRsp.Counter, handle.Handle)

	if err != nil {
		return nil, fmt.Errorf("sign error: %v\n", err)
	}

	/* calc hash c = H( n | c2 ) */
	hash = newHash()
	hash.writeBIG(n)
	hash.writeBytes(c2Buf)
	c := hash.sumToBIG()

	proof := SchnorrProof{
		SmallC: c,
		SmallS: s,
		SmallN: n,
		K:      K,
	}

	signature := Signature{
		Proof:          &proof,
		RandomizedCred: randomizedCred,
	}

	return &signature, nil
}

func Verify(message, basename []byte, signature *Signature, ipk *IPK, rl RevocationList) error {
	err := verifySchnorr(message, basename, signature.Proof, nil, signature.RandomizedCred.B, signature.RandomizedCred.D)

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
