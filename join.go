package ecdaa

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"

	"github.com/akakou-fork/amcl-go/miracl/core"

	"github.com/akakou-fork/amcl-go/miracl/core/FP256BN"
	amcl_utils "github.com/akakou/fp256bn-amcl-utils"

	"github.com/akakou/ecdaa/tpm_utils"
)

type JoinSeed struct {
	Basename []byte
	S2       []byte
	Y2       *FP256BN.BIG
}

func GenJoinSeed(rng *core.RAND) (*JoinSeed, *FP256BN.ECP, error) {
	var seed JoinSeed
	basename := amcl_utils.RandomBytes(rng, 32)

	hash := amcl_utils.NewHash()
	hash.WriteBytes(basename)

	B, i, err := hash.HashToECP()

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

type JoinRequest struct {
	Proof *SchnorrProof
	Q     *FP256BN.ECP
}

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
	sk := amcl_utils.RandomBig(rng)

	/* set zero buffers to P1 */
	hash := amcl_utils.NewHash()
	hash.WriteBytes(seed.S2)
	bX := hash.SumToBIG()

	B := FP256BN.NewECPbigs(bX, seed.Y2)
	// get result (Q)
	Q := B.Mul(sk)

	proof := proveSchnorr([]byte(""), nil, sk, B, Q, rng)

	req := JoinRequest{
		proof,
		Q,
	}

	return &req, sk, nil
}

func GenJoinReqWithTPM(seed *JoinSeed, tpm *tpm_utils.TPM, rng *core.RAND) (*JoinRequestTPM, *KeyHandles, error) {
	/* create key and get public key */
	handle, ekHandle, srkHandle, _, err := tpm.CreateKey()

	if err != nil {
		return nil, nil, err
	}

	hash := amcl_utils.NewHash()
	hash.WriteBytes(seed.S2)
	bX := hash.SumToBIG()

	B := FP256BN.NewECPbigs(bX, seed.Y2)

	/* run commit and get U1 */
	comRsp, E, _, K, err := (*tpm).Commit(handle, B, seed.S2, B)

	if err != nil {
		return nil, nil, fmt.Errorf("commit error: %v", err)
	}

	/* calc hash c2 = H( U1 | P1 | Q | m ) */
	hash = amcl_utils.NewHash()
	hash.WriteECP(E, B, K)
	c2 := hash.SumToBIG()

	/* sign and get s1, n */
	c2Buf := amcl_utils.BigToBytes(c2)

	_, s1, n, err := (*tpm).Sign(c2Buf[:], comRsp.Counter, handle)

	if err != nil {
		return nil, nil, fmt.Errorf("sign error: %v", err)
	}

	/* calc hash c1 = H( n | c2 ) */
	hash = amcl_utils.NewHash()
	hash.WriteBIG(n)
	hash.WriteBytes(c2Buf[:])
	c1 := hash.SumToBIG()

	EKCert, err := (*tpm).ReadEKCert()

	if err != nil {
		return nil, nil, fmt.Errorf("sign error: %v", err)
	}

	proof := SchnorrProof{
		SmallC: c1,
		SmallN: n,
		SmallS: s1,
	}

	req := JoinRequest{
		Proof: &proof,
		Q:     K,
	}

	reqTPM := JoinRequestTPM{
		EKCert:  EKCert,
		JoinReq: &req,
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
	err := verifySchnorr([]byte(""), nil, req.Proof, B, req.Q)

	return err
}
