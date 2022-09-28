package ecdaa

import "miracl/core/FP256BN"

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

