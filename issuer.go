package main

import (
	"errors"
	"miracl/core"
	"miracl/core/FP256BN"
)

type ISK struct {
	x *FP256BN.BIG
	y *FP256BN.BIG
}

func RandomISK(rng *core.RAND) ISK {
	var isk ISK
	x := FP256BN.Random(rng)
	y := FP256BN.Random(rng)

	isk.x = x
	isk.y = y

	return isk
}

type IPK struct {
	X   *FP256BN.ECP2
	Y   *FP256BN.ECP2
	c   *FP256BN.BIG
	s_x *FP256BN.BIG
	s_y *FP256BN.BIG
}

func RandomIPK(isk *ISK, rng *core.RAND) IPK {
	// random r_x, r_y
	var ipk IPK

	x := isk.x
	y := isk.y

	r_x := FP256BN.Random(rng)
	r_y := FP256BN.Random(rng)

	// calc X, Y
	// X = g2^x
	// Y = g2^y
	X := FP256BN.ECP2_generator().Mul(x)
	Y := FP256BN.ECP2_generator().Mul(y)

	// calc U_x, U_y
	//     U_x = g2 ^ r_x
	//     U_y = g2 ^ r_y
	U_x := FP256BN.ECP2_generator().Mul(r_x)
	U_y := FP256BN.ECP2_generator().Mul(r_y)

	// calc `c = H(U_x | U_y | X | Y)`
	c := HashECP2s(U_x, U_y, X, Y)

	// calc s_x, s_y
	//     s_x = r_x + cx
	//     s_y = r_y + cy
	// todo: mod p
	s_x := FP256BN.Modmul(c, x, p())
	s_x = FP256BN.Modadd(r_x, s_x, p())

	s_y := FP256BN.NewBIG()
	s_y = FP256BN.Modmul(y, c, p())
	s_y = FP256BN.Modadd(r_y, s_y, p())

	// copy pointers to ipk
	ipk.X = X
	ipk.Y = Y
	ipk.c = c
	ipk.s_x = s_x
	ipk.s_y = s_y

	return ipk
}

func VerifyIPK(ipk *IPK) error {
	X := ipk.X
	Y := ipk.Y
	c := ipk.c
	s_x := ipk.s_x
	s_y := ipk.s_y

	// calc minus c = -c
	minusC := FP256BN.Modneg(c, p())

	// calc U_x = g2^s_x * X^{-c}
	U_x := FP256BN.ECP2_generator().Mul(s_x)
	tmp := X.Mul(minusC)
	U_x.Add(tmp)

	// calc U_y = g2^s_y * Y^{-c}
	U_y := FP256BN.ECP2_generator().Mul(s_y)
	tmp = Y.Mul(minusC)
	U_y.Add(tmp)

	// hashing
	cDash := HashECP2s(U_x, U_y, X, Y)

	if FP256BN.Comp(c, cDash) == 0 {
		return nil
	} else {
		return errors.New("IPK is not valid\n")
	}
}
