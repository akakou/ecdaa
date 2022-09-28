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
