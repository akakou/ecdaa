package ecdaa

import (
	"crypto/rsa"
	"fmt"
	"miracl/core"
	"miracl/core/FP256BN"

	legacy "github.com/google/go-tpm/legacy/tpm2"
)

type Credential struct {
	A, B, C, D *FP256BN.ECP
}

type CredentialCipher struct {
	A, C []byte

	WrappedCredential []byte
	IdObject          []byte
	EncA              []byte
	EncC              []byte
	IV                []byte
}

/**
 * Step3. make credential for join (by Issuer)
 */
func (issuer *Issuer) MakeCred(req *JoinRequest, B *FP256BN.ECP, rng *core.RAND) (*Credential, error) {
	var cred Credential

	invY := FP256BN.NewBIGcopy(issuer.Isk.Y)
	invY.Invmodp(p())

	cred.A = B.Mul(invY)

	cred.C = FP256BN.NewECP()
	cred.C.Copy(cred.A)
	cred.C.Add(req.Q)
	cred.C = cred.C.Mul(issuer.Isk.X)

	cred.B = B
	cred.D = req.Q

	return &cred, nil
}

func (issuer *Issuer) MakeCredEncrypted(req *JoinRequestTPM, B *FP256BN.ECP, rng *core.RAND) (*CredentialCipher, *Credential, error) {
	var credCipher CredentialCipher

	secret := randomBytes(rng, 16)
	iv := randomBytes(rng, 16)

	cred, err := issuer.MakeCred(req.JoinReq, B, rng)

	if err != nil {
		return nil, nil, fmt.Errorf("enc cred: %v", err)
	}

	ABuf := ecpToBytes(cred.A)
	CBuf := ecpToBytes(cred.C)

	credCipher.A, credCipher.C, err = encCredAES(ABuf, CBuf, secret, iv)

	if err != nil {
		return nil, nil, fmt.Errorf("enc cred: %v", err)
	}

	aikName := legacy.HashValue{
		Alg:   legacy.AlgSHA256,
		Value: req.SrkName,
	}

	pub := req.EKCert.PublicKey.(*rsa.PublicKey)

	credCipher.IdObject, credCipher.WrappedCredential, err = MakeCred(&aikName, pub, 16, secret)

	if err != nil {
		return nil, nil, fmt.Errorf("enc cred: %v", err)
	}
	credCipher.IV = iv

	return &credCipher, cred, nil
}

// /**
//  * Step4. activate credential for join with TPM2_activate_credential (by Member)
//  */
// func (member *Member) ActivateCredential(encCred *CredentialCipher, ipk *IPK, EkHandle, SrkHandle) (*Credential, error) {
// 	var cred Credential
// 	secret, err := (*member.Tpm).ActivateCredential(EkHandle, SrkHandle, encCred.IdObject, encCred.WrappedCredential)

// 	if err != nil {
// 		return nil, err
// 	}

// 	decA, decC, err := decCredAES(encCred.EncA, encCred.EncC, secret, encCred.IV)

// 	if err != nil {
// 		return nil, err
// 	}

// 	cred.A = FP256BN.ECP_fromBytes(decA)
// 	cred.C = FP256BN.ECP_fromBytes(decC)

// 	tmp := FP256BN.NewECP()
// 	tmp.Copy(cred.A)
// 	tmp.Add(cred.D)

// 	a := FP256BN.Ate(ipk.Y, cred.A)
// 	b := FP256BN.Ate(g2(), cred.B)

// 	a = FP256BN.Fexp(a)
// 	b = FP256BN.Fexp(b)

// 	if !a.Equals(b) {
// 		return nil, fmt.Errorf("Ate(ipk.Y, cred.A) != Ate(g2(), cred.B)")
// 	}

// 	c := FP256BN.Ate(g2(), cred.C)
// 	d := FP256BN.Ate(ipk.X, tmp)

// 	c = FP256BN.Fexp(c)
// 	d = FP256BN.Fexp(d)

// 	if !c.Equals(d) {
// 		return nil, fmt.Errorf("Ate(g2(), cred.C) != Ate(ipk.X, tmp)")
// 	}

// 	return &cred, nil
// }
