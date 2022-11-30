package ecdaa

import (
	"crypto/x509"
	"miracl/core/FP256BN"

	"github.com/google/go-tpm/tpm2"
)

type MiddleEncodedISK struct {
	X []byte
	Y []byte
}

func (isk *ISK) Encode() *MiddleEncodedISK {
	var encoded MiddleEncodedISK

	encoded.X = bigToBytes(isk.X)
	encoded.Y = bigToBytes(isk.Y)

	return &encoded
}

func (encoded *MiddleEncodedISK) Decode() *ISK {
	var isk ISK

	isk.X = FP256BN.FromBytes(encoded.X)
	isk.Y = FP256BN.FromBytes(encoded.Y)

	return &isk
}

type MiddleEncodedIPK struct {
	X  []byte
	Y  []byte
	C  []byte
	SX []byte
	SY []byte
}

func (ipk *IPK) Encode() *MiddleEncodedIPK {
	var encoded MiddleEncodedIPK

	encoded.X = ecp2ToBytes(ipk.X)
	encoded.Y = ecp2ToBytes(ipk.Y)
	encoded.C = bigToBytes(ipk.C)
	encoded.SX = bigToBytes(ipk.SX)
	encoded.SY = bigToBytes(ipk.SY)

	return &encoded
}

func (encoded *MiddleEncodedIPK) Decode() *IPK {
	var decoded IPK

	decoded.X = FP256BN.ECP2_fromBytes(encoded.X)
	decoded.Y = FP256BN.ECP2_fromBytes(encoded.Y)
	decoded.C = FP256BN.FromBytes(encoded.C)
	decoded.SX = FP256BN.FromBytes(encoded.SX)
	decoded.SY = FP256BN.FromBytes(encoded.SY)

	return &decoded
}

type MiddleEncodedCredential struct {
	A []byte
	B []byte
	C []byte
	D []byte
}

func (cred *Credential) Encode() *MiddleEncodedCredential {
	var encoded MiddleEncodedCredential

	encoded.A = ecpToBytes(cred.A)
	encoded.B = ecpToBytes(cred.B)
	encoded.C = ecpToBytes(cred.C)
	encoded.D = ecpToBytes(cred.D)

	return &encoded
}

func (encoded *MiddleEncodedCredential) Decode() *Credential {
	var decoded Credential

	decoded.A = FP256BN.ECP_fromBytes(encoded.A)
	decoded.B = FP256BN.ECP_fromBytes(encoded.B)
	decoded.C = FP256BN.ECP_fromBytes(encoded.C)
	decoded.D = FP256BN.ECP_fromBytes(encoded.D)

	return &decoded
}

type MiddleEncodedSignature struct {
	SmallC []byte
	SmallN []byte
	SmallS []byte
	R      []byte
	S      []byte
	T      []byte
	W      []byte
	K      []byte
}

func (sig *Signature) Encode() *MiddleEncodedSignature {
	var encoded MiddleEncodedSignature

	encoded.SmallC = bigToBytes(sig.SmallC)
	encoded.SmallN = bigToBytes(sig.SmallN)
	encoded.SmallS = bigToBytes(sig.SmallS)
	encoded.R = ecpToBytes(sig.R)
	encoded.S = ecpToBytes(sig.S)
	encoded.T = ecpToBytes(sig.T)
	encoded.W = ecpToBytes(sig.W)
	encoded.K = ecpToBytes(sig.K)

	return &encoded
}

func (encoded *MiddleEncodedSignature) Decode() *Signature {
	var decoded Signature

	decoded.SmallC = FP256BN.FromBytes(encoded.SmallC)
	decoded.SmallN = FP256BN.FromBytes(encoded.SmallN)
	decoded.SmallS = FP256BN.FromBytes(encoded.SmallS)
	decoded.R = FP256BN.ECP_fromBytes(encoded.R)
	decoded.S = FP256BN.ECP_fromBytes(encoded.S)
	decoded.T = FP256BN.ECP_fromBytes(encoded.T)
	decoded.W = FP256BN.ECP_fromBytes(encoded.W)
	decoded.K = FP256BN.ECP_fromBytes(encoded.K)

	return &decoded
}

type MiddleEncodedJoinSeeds struct {
	Basename []byte
	S2       []byte
	Y2       []byte
}

func (seeds *JoinSeeds) Encode() *MiddleEncodedJoinSeeds {
	var encoded MiddleEncodedJoinSeeds
	encoded.Basename = seeds.Basename
	encoded.S2 = seeds.S2
	encoded.Y2 = bigToBytes(seeds.Y2)

	return &encoded
}

func (encoded *MiddleEncodedJoinSeeds) Decode() *JoinSeeds {
	var decoded JoinSeeds
	decoded.Basename = encoded.Basename
	decoded.S2 = encoded.S2
	decoded.Y2 = FP256BN.FromBytes(encoded.Y2)

	return &decoded
}

type MiddleEncodedJoinRequest struct {
	Public  []byte
	EKCert  []byte
	C1      []byte
	S1      []byte
	N       []byte
	Q       []byte
	SrkName []byte
}

func (request *JoinRequest) Encode() *MiddleEncodedJoinRequest {
	var encoded MiddleEncodedJoinRequest
	public, err := tpm2.Marshal(request.Public)

	if err != nil {
		panic(err)
	}

	encoded.Public = public
	encoded.EKCert = request.EKCert.Raw

	encoded.C1 = bigToBytes(request.C1)
	encoded.S1 = bigToBytes(request.S1)
	encoded.N = bigToBytes(request.N)
	encoded.Q = ecpToBytes(request.Q)

	encoded.SrkName = request.SrkName

	return &encoded
}

func (encoded *MiddleEncodedJoinRequest) Decode() (*JoinRequest, error) {
	var decoded JoinRequest

	var pub tpm2.TPM2BPublic
	err := tpm2.Unmarshal(encoded.Public, &pub)

	if err != nil {
		return nil, err
	}

	decoded.Public = &pub
	decoded.EKCert, err = x509.ParseCertificate(encoded.EKCert)

	if err != nil {
		return nil, err
	}

	decoded.C1 = FP256BN.FromBytes(encoded.C1)
	decoded.S1 = FP256BN.FromBytes(encoded.S1)
	decoded.N = FP256BN.FromBytes(encoded.N)
	decoded.Q = FP256BN.ECP_fromBytes(encoded.Q)

	decoded.SrkName = encoded.SrkName

	return &decoded, nil
}

type MiddleEncodedCredCipher struct {
	WrappedCredential []byte
	IdObject          []byte
	EncA              []byte
	EncC              []byte
	IV                []byte
}

func (cipher *CredCipher) Encode() *MiddleEncodedCredCipher {
	var encoded MiddleEncodedCredCipher

	encoded.WrappedCredential = cipher.WrappedCredential
	encoded.IdObject = cipher.IdObject

	encoded.EncA = cipher.EncA
	encoded.EncC = cipher.EncC

	encoded.IV = cipher.IV

	return &encoded
}

func (encoded *MiddleEncodedCredCipher) Decode() *CredCipher {
	var decoded CredCipher

	decoded.WrappedCredential = encoded.WrappedCredential
	decoded.IdObject = encoded.IdObject

	decoded.EncA = encoded.EncA
	decoded.EncC = encoded.EncC

	decoded.IV = encoded.IV

	return &decoded
}

func EncodeRevocationList(list RevocationList) [][]byte {
	var result [][]byte

	for _, sk := range list {
		encoded := bigToBytes(sk)
		result = append(result, encoded)
	}

	return result
}

func DecodeRevocationList(list [][]byte) RevocationList {
	result := RevocationList{}

	for _, sk := range list {
		decoded := FP256BN.FromBytes(sk)
		result = append(result, decoded)
	}

	return result
}
