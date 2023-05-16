package ecdaa

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"miracl/core"
	"miracl/core/FP256BN"
)

type JoinSeed struct {
	Basename []byte
	S2       []byte
	Y2       *FP256BN.BIG
}

func GenJoinSeed(rng *core.RAND) (*JoinSeed, *FP256BN.ECP, error) {
	var seed JoinSeed
	basename := randomBytes(rng, 32)

	hash := newHash()
	hash.writeBytes(basename)

	B, i, err := hash.hashToECP()

	if err != nil {
		return nil, nil, err
	}

	numBuf := make([]byte, binary.MaxVarintLen32)
	binary.PutVarint(numBuf, int64(i))

	s2Buf := append(numBuf, basename[:]...)

	seed.Basename = basename[:]
	seed.S2 = s2Buf
	seed.Y2 = B.GetY()

	return &seed, B, nil
}

type JoinRequest = SchnorrProof

type JoinRequestTPM struct {
	JoinReq *JoinRequest
	EKCert  *x509.Certificate
	SrkName []byte
}

/**
 * Step2. generate request for join (by Member)
 */
func GenJoinReq(seed *JoinSeed, rng *core.RAND) (*JoinRequest, *FP256BN.BIG, error) {
	/* create key and get public key */
	sk := randomBig(rng)

	/* set zero buffers to P1 */
	hash := newHash()
	hash.writeBytes(seed.S2)
	bX := hash.sumToBIG()

	B := FP256BN.NewECPbigs(bX, seed.Y2)
	// get result (Q)

	// remove B
	proof := proveSchnorr([]byte(""), nil, sk, B, nil, rng)

	return proof, sk, nil
}

func GenReqForJoinWithTPM(seed *JoinSeed, tpm *TPM, rng *core.RAND) (*JoinRequestTPM, *KeyHandles, error) {
	/* create key and get public key */
	handle, ekHandle, srkHandle, _, err := tpm.CreateKey()

	if err != nil {
		return nil, nil, err
	}

	hash := newHash()
	hash.writeBytes(seed.S2)
	bX := hash.sumToBIG()

	B := FP256BN.NewECPbigs(bX, seed.Y2)

	/* run commit and get U1 */
	comRsp, E, _, K, err := (*tpm).Commit(handle, B, seed.S2, B)

	if err != nil {
		return nil, nil, fmt.Errorf("commit error: %v", err)
	}

	/* calc hash c2 = H( U1 | P1 | Q | m ) */
	hash = newHash()
	hash.writeECP(E, B, K)
	c2 := hash.sumToBIG()

	/* sign and get s1, n */
	c2Buf := bigToBytes(c2)

	_, s1, n, err := (*tpm).Sign(c2Buf[:], comRsp.Counter, handle)

	if err != nil {
		return nil, nil, fmt.Errorf("sign error: %v", err)
	}

	/* calc hash c1 = H( n | c2 ) */
	hash = newHash()
	hash.writeBIG(n)
	hash.writeBytes(c2Buf[:])
	c1 := hash.sumToBIG()

	EKCert, err := (*tpm).ReadEKCert()

	if err != nil {
		return nil, nil, fmt.Errorf("sign error: %v", err)
	}

	proof := SchnorrProof{
		SmallC: c1,
		SmallN: n,
		SmallS: s1,
	}

	reqTPM := JoinRequestTPM{
		EKCert:  EKCert,
		JoinReq: &proof,
		SrkName: srkHandle.Name.Buffer,
	}

	keyHandles := KeyHandles{
		EkHandle:  ekHandle,
		SrkHandle: srkHandle,
		Handle:    handle,
	}

	return &reqTPM, &keyHandles, nil
}

func VerifyJoinReq(req *JoinRequest, seed *JoinSeed, B *FP256BN.ECP) error {
	err := verifySchnorr([]byte(""), nil, req, B, req.K)

	return err
}
