package ecdaa

import (
	"encoding/binary"
	"fmt"
	"miracl/core"
	"miracl/core/FP256BN"

	"github.com/anonymous/mcl_utils"

	"github.com/anonymous/ecdaa/tools"
	"github.com/anonymous/ecdaa/tpm_utils"
	"github.com/google/go-tpm/tpm2"
)

type RevocationList = []*FP256BN.BIG

type Member struct {
	Tpm        *tpm_utils.TPM
	KeyHandles *KeyHandles
}

type KeyHandles struct {
	EkHandle  *tpm2.AuthHandle
	SrkHandle *tpm2.NamedHandle
	Handle    *tpm2.AuthHandle
}

func NewMember(tpm *tpm_utils.TPM) Member {
	var member = Member{
		Tpm: tpm,
	}

	return member
}

type Signature struct {
	Proof          *SchnorrProof
	RandomizedCred *Credential
}

type SWSigner struct {
	cred *Credential
	sk   *FP256BN.BIG
}

type TPMSigner struct {
	cred   *Credential
	handle *KeyHandles
	tpm    *tpm_utils.TPM
}

func NewSWSigner(cred *Credential, sk *FP256BN.BIG) SWSigner {
	var signer = SWSigner{
		cred: cred,
		sk:   sk,
	}

	return signer
}

func NewTPMSigner(cred *Credential, handle *KeyHandles, tpm *tpm_utils.TPM) TPMSigner {
	var signer = TPMSigner{
		cred:   cred,
		handle: handle,
		tpm:    tpm,
	}

	return signer
}

type Signer interface {
	Sign(message, basename []byte, rng *core.RAND) (*Signature, error)
}

func (signer SWSigner) Sign(
	message,
	basename []byte,
	rng *core.RAND) (*Signature, error) {

	randomizedCred := RandomizeCred(signer.cred, rng)
	proof := proveSchnorr(message, basename, signer.sk, randomizedCred.B, randomizedCred.D, rng)

	return &Signature{
		Proof:          proof,
		RandomizedCred: randomizedCred,
	}, nil
}

func (signer *TPMSigner) Sign(message, basename []byte, rng *core.RAND) (*Signature, error) {
	hash := tools.NewHash()
	hash.WriteBytes(basename)

	B, i, err := hash.HashToECP()

	if err != nil {
		return nil, err
	}

	numBuf := make([]byte, binary.MaxVarintLen32)
	binary.PutVarint(numBuf, int64(i))

	s2Buf := append(numBuf, basename[:]...)

	randomizedCred := RandomizeCred(signer.cred, rng)
	S := randomizedCred.B
	W := randomizedCred.D

	/* run commit and get U */
	comRsp, E, L, K, err := (*signer.tpm).Commit(signer.handle.Handle, S, s2Buf, B)

	if err != nil {
		return nil, fmt.Errorf("commit error: %v", err)
	}

	// c2 = H(E, S, W, L, B, K,basename, message)
	hash = tools.NewHash()
	hash.WriteECP(E, S, W, L, B, K)
	hash.WriteBytes(basename, message)

	c2 := hash.SumToBIG()

	/* sign and get s1, n */
	c2Buf := mcl_utils.BigToBytes(c2)

	_, s, n, err := (*signer.tpm).Sign(c2Buf, comRsp.Counter, signer.handle.Handle)

	if err != nil {
		return nil, fmt.Errorf("sign error: %v", err)
	}

	/* calc hash c = H( n | c2 ) */
	hash = tools.NewHash()
	hash.WriteBIG(n)
	hash.WriteBytes(c2Buf)
	c := hash.SumToBIG()

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
