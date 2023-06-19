package ecdaa

import (
	"crypto/rsa"
	"fmt"
	"miracl/core"
	"miracl/core/FP256BN"

	"github.com/akakou/ecdaa/tpm_utils"
	"github.com/akakou/mcl_utils"
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
	invY.Invmodp(mcl_utils.P())

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

	secret := mcl_utils.RandomBytes(rng, 16)
	iv := mcl_utils.RandomBytes(rng, 16)

	cred, err := issuer.MakeCred(req.JoinReq, B, rng)

	if err != nil {
		return nil, nil, fmt.Errorf("enc cred: %v", err)
	}

	ABuf := mcl_utils.EcpToBytes(cred.A)
	CBuf := mcl_utils.EcpToBytes(cred.C)

	credCipher.A, credCipher.C, err = tpm_utils.EncCredAES(ABuf, CBuf, secret, iv)

	if err != nil {
		return nil, nil, fmt.Errorf("enc cred: %v", err)
	}

	aikName := legacy.HashValue{
		Alg:   legacy.AlgSHA256,
		Value: req.SrkName,
	}

	pub := req.EKCert.PublicKey.(*rsa.PublicKey)

	credCipher.IdObject, credCipher.WrappedCredential, err = tpm_utils.MakeCred(&aikName, pub, 16, secret)

	if err != nil {
		return nil, nil, fmt.Errorf("enc cred: %v", err)
	}
	credCipher.IV = iv

	return &credCipher, cred, nil
}

func VerifyCred(cred *Credential, ipk *IPK) error {
	tmp := FP256BN.NewECP()
	tmp.Copy(cred.A)
	tmp.Add(cred.D)

	a := FP256BN.Ate(ipk.Y, cred.A)
	b := FP256BN.Ate(mcl_utils.G2(), cred.B)

	a = FP256BN.Fexp(a)
	b = FP256BN.Fexp(b)

	if !a.Equals(b) {
		return fmt.Errorf("Ate(ipk.Y, cred.A) != Ate(g2(), cred.B)")
	}

	c := FP256BN.Ate(mcl_utils.G2(), cred.C)
	d := FP256BN.Ate(ipk.X, tmp)

	c = FP256BN.Fexp(c)
	d = FP256BN.Fexp(d)

	if !c.Equals(d) {
		return fmt.Errorf("Ate(g2(), cred.C) != Ate(ipk.X, tmp)")
	}

	return nil
}

/**
 * Step4. activate credential for join with TPM2_activate_credential (by Member)
 */
func ActivateCredential(
	encCred *CredentialCipher,
	B, D *FP256BN.ECP,
	ipk *IPK,
	handle *KeyHandles,
	tpm *tpm_utils.TPM) (*Credential, error) {
	secret, err := (*tpm).ActivateCredential(handle.EkHandle, handle.SrkHandle, encCred.IdObject, encCred.WrappedCredential)

	if err != nil {
		return nil, err
	}

	decA, decC, err := tpm_utils.DecCredAES(encCred.A, encCred.C, secret, encCred.IV)

	if err != nil {
		return nil, err
	}

	A := FP256BN.ECP_fromBytes(decA)
	C := FP256BN.ECP_fromBytes(decC)

	cred := Credential{
		A, B, C, D,
	}

	return &cred, nil
}

func RandomizeCred(cred *Credential, rng *core.RAND) *Credential {
	var randomized Credential

	l := FP256BN.Random(rng)

	randomized.A = cred.A.Mul(l)
	randomized.B = cred.B.Mul(l)
	randomized.C = cred.C.Mul(l)
	randomized.D = cred.D.Mul(l)

	return &randomized
}
