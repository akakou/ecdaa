package main

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"miracl/core"
	"miracl/core/FP256BN"

	"github.com/google/go-tpm/tpm2"
)

type JoinSeeds struct {
	Basename []byte
	S2       []byte
	Y2       *FP256BN.BIG
}

type JoinRequest struct {
	Public   *tpm2.TPM2BPublic
	Cert     *x509.Certificate
	C1       *FP256BN.BIG
	S1       *FP256BN.BIG
	N        *FP256BN.BIG
	Q        *FP256BN.ECP
	ekHandle *tpm2.AuthHandle // not good
	srkName  string           // not good
}

type CredCipher struct {
	WrapSymmetric []byte
	EncSeed       []byte
	EncA          []byte
	EncC          []byte
	IV            []byte
}

type IssuerJoinSession struct {
	// B *FP256BN.ECP
	cred Credential
}

type MemberSession struct {
	B *FP256BN.ECP
	D *FP256BN.ECP

	srkHandle *tpm2.NamedHandle
	ekHandle  *tpm2.AuthHandle
}

/**
 * Step1. generate seed for join (by Issuer)
 */
func (_ *Issuer) GenSeedForJoin(rng *core.RAND) (*JoinSeeds, *IssuerJoinSession, error) {
	var seed JoinSeeds
	var session IssuerJoinSession

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

	session.cred.B = B

	return &seed, &session, nil
}

/**
 * Step2. generate request for join (by Member)
 */
func (member *Member) GenReqForJoin(seeds *JoinSeeds, rng *core.RAND) (*JoinRequest, *MemberSession, error) {
	var req JoinRequest
	var session MemberSession

	/* create key and get public key */
	handle, ekHandle, srkHandle, _, err := (*member.Tpm).CreateKey()

	if err != nil {
		return nil, nil, err
	}

	/* set zero buffers to P1 */
	hash := newHash()
	hash.writeBytes(seeds.S2)
	bX := hash.sumToBIG()

	B := FP256BN.NewECPbigs(bX, seeds.Y2)

	xBuf := bigToBytes(B.GetX())
	yBuf := bigToBytes(B.GetY())

	P1 := tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{
			Buffer: xBuf,
		},
		Y: tpm2.TPM2BECCParameter{
			Buffer: yBuf,
		},
	}

	/* set up argument for commit */
	S2 := tpm2.TPM2BSensitiveData{
		Buffer: seeds.S2[:],
	}

	Y2 := tpm2.TPM2BECCParameter{
		Buffer: yBuf,
	}

	/* run commit and get U1 */
	comRsp, err := (*member.Tpm).Commit(handle, &P1, &S2, &Y2)

	if err != nil {
		return nil, nil, fmt.Errorf("commit error: %v\n", err)
	}

	// get result (Q)
	K := parseECPFromTPMFmt(&comRsp.K.Point)
	Q := K

	// get result (U1)
	E := parseECPFromTPMFmt(&comRsp.E.Point)
	U1 := E

	/* calc hash c2 = H( U1 | P1 | Q | m ) */
	hash = newHash()

	hash.writeECP(U1, B, Q)

	c2 := hash.sumToBIG()

	/* sign and get s1, n */
	c2Buf := bigToBytes(c2)

	sign, err := (*member.Tpm).Sign(c2Buf[:], comRsp.Counter, handle)

	if err != nil {
		return nil, nil, fmt.Errorf("sign error: %v\n", err)
	}

	s1 := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureS.Buffer)
	n := FP256BN.FromBytes(sign.Signature.Signature.ECDAA.SignatureR.Buffer)

	/* calc hash c1 = H( n | c2 ) */
	hash = newHash()
	hash.writeBIG(n)
	hash.writeBytes(c2Buf[:])
	c1 := hash.sumToBIG()

	req.S1 = s1
	req.C1 = c1
	req.N = n

	// todo: remove
	req.Q = Q
	req.Cert, err = (*member.Tpm).ReadEKCert()

	session.B = B
	session.D = Q

	session.ekHandle = ekHandle
	session.srkHandle = srkHandle

	keyHandles := KeyHandles{
		EkHandle:  ekHandle,
		SrkHandle: srkHandle,
		Handle:    handle,
	}

	member.KeyHandles = &keyHandles

	// todo: remove
	req.ekHandle = ekHandle
	req.srkName = string(srkHandle.Name.Buffer)

	return &req, &session, nil
}

/**
 * Step3. make credential for join (by Issuer)
 */
func (issuer *Issuer) MakeCred(req *JoinRequest, session *IssuerJoinSession, rng *core.RAND) (*CredCipher, error) {
	var encCred CredCipher

	B := session.cred.B
	Q := req.Q

	U1 := B.Mul(req.S1)
	UTmp := Q.Mul(req.C1)

	U1.Sub(UTmp)
	U1.Affine()

	hash := newHash()
	hash.writeECP(U1, B, Q)
	c2 := hash.sumToBIG()

	c2Buf := bigToBytes(c2)

	hash = newHash()
	hash.writeBIG(req.N)
	hash.writeBytes(c2Buf[:])
	c1 := hash.sumToBIG()

	if FP256BN.Comp(c1, req.C1) != 0 {
		return nil, fmt.Errorf("U is not match (`%v` != `%v`)", c1.ToString(), req.C1.ToString())
	}

	var cred Credential

	invY := FP256BN.NewBIGcopy(issuer.Isk.Y)
	invY.Invmodp(p())

	cred.A = B.Mul(invY)

	cred.B = B
	cred.C = FP256BN.NewECP()
	cred.C.Copy(cred.A)
	cred.C.Add(Q)
	cred.C = cred.C.Mul(issuer.Isk.X)

	cred.D = Q

	secret := tpm2.TPM2BDigest{Buffer: randomBytes(rng, 16)}
	iv := randomBytes(rng, 16)

	ABuf := ecpToBytes(cred.A)
	CBuf := ecpToBytes(cred.C)

	var err error
	encCred.EncA, encCred.EncC, err = encCredAES(ABuf, CBuf, secret.Buffer, iv)

	if err != nil {
		return nil, fmt.Errorf("enc cred: %v", err)
	}

	tpm, err := OpenRealTPM()
	defer tpm.Close()

	if err != nil {
		return nil, err
	}

	mc := tpm2.MakeCredential{
		Handle:     req.ekHandle.Handle,
		Credential: secret,
		ObjectNamae: tpm2.TPM2BName{
			Buffer: []byte(req.srkName),
		},
	}

	mcRsp, err := mc.Execute(tpm.tpm)
	if err != nil {
		return nil, fmt.Errorf("make credential: %v", err)
	}

	encCred.WrapSymmetric = mcRsp.CredentialBlob.Buffer
	encCred.EncSeed = mcRsp.Secret.Buffer
	encCred.IV = iv

	session.cred = cred

	return &encCred, nil
}

/**
 * Step4. activate credential for join with TPM2_activate_credential (by Member)
 */
func (member *Member) ActivateCredential(encCred *CredCipher, session *MemberSession, ipk *IPK) (*Credential, error) {
	var cred Credential
	secret, err := (*member.Tpm).ActivateCredential(session.ekHandle, session.srkHandle, encCred.WrapSymmetric, encCred.EncSeed)

	if err != nil {
		return nil, err
	}

	decA, decC, err := decCredAES(encCred.EncA, encCred.EncC, secret, encCred.IV)

	if err != nil {
		return nil, err
	}

	cred.A = FP256BN.ECP_fromBytes(decA)
	cred.C = FP256BN.ECP_fromBytes(decC)

	cred.B = session.B
	cred.D = session.D

	tmp := FP256BN.NewECP()
	tmp.Copy(cred.A)
	tmp.Add(cred.D)

	a := FP256BN.Ate(ipk.Y, cred.A)
	b := FP256BN.Ate(g2(), cred.B)

	a = FP256BN.Fexp(a)
	b = FP256BN.Fexp(b)

	if !a.Equals(b) {
		return nil, fmt.Errorf("Ate(ipk.Y, cred.A) != Ate(g2(), cred.B)")
	}

	c := FP256BN.Ate(g2(), cred.C)
	d := FP256BN.Ate(ipk.X, tmp)

	c = FP256BN.Fexp(c)
	d = FP256BN.Fexp(d)

	if !c.Equals(d) {
		return nil, fmt.Errorf("Ate(g2(), cred.C) != Ate(ipk.X, tmp)")
	}

	return &cred, nil
}
