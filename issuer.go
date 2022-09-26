package main

import (
	"errors"
	"miracl/core"
	"miracl/core/FP256BN"
)

/**
 * ISK: Issuer's Secret Key.
 */
type ISK struct {
	x *FP256BN.BIG
	y *FP256BN.BIG
}

/**
 * Generate IPK with random.
 */
func RandomISK(rng *core.RAND) ISK {
	var isk ISK
	x := FP256BN.Random(rng)
	y := FP256BN.Random(rng)

	x.Mod(p())
	y.Mod(p())

	isk.x = x
	isk.y = y

	return isk
}

/**
 * IPL: Issuer's Public Key.
 */
type IPK struct {
	X  *FP256BN.ECP2
	Y  *FP256BN.ECP2
	c  *FP256BN.BIG
	sX *FP256BN.BIG
	sY *FP256BN.BIG
}

/**
 * Generate IPK with random and ISK.
 */
func RandomIPK(isk *ISK, rng *core.RAND) IPK {
	// random r_x, r_y
	var ipk IPK

	x := isk.x
	y := isk.y

	rX := FP256BN.Random(rng)
	rY := FP256BN.Random(rng)

	rX.Mod(p())
	rY.Mod(p())

	// calc X, Y
	// X = g2^x
	// Y = g2^y
	X := g2().Mul(x)
	Y := g2().Mul(y)

	// calc U_x, U_y
	//     U_x = g2 ^ r_x
	//     U_y = g2 ^ r_y
	Ux := g2().Mul(rX)
	Uy := g2().Mul(rY)

	// calc `c = H(U_x | U_y | g2 | X | Y)`
	hash := NewHash()
	hash.WriteECP2(Ux, Uy, g2(), X, Y)
	c := hash.SumToBIG()

	// calc s_x, s_y
	//     s_x = r_x + cx
	//     s_y = r_y + cy
	// todo: mod p
	sX := FP256BN.Modmul(c, x, p())
	sX = FP256BN.Modadd(rX, sX, p())

	sY := FP256BN.NewBIG()
	sY = FP256BN.Modmul(y, c, p())
	sY = FP256BN.Modadd(rY, sY, p())

	// copy pointers to ipk
	ipk.X = X
	ipk.Y = Y
	ipk.c = c
	ipk.sX = sX
	ipk.sY = sY

	return ipk
}

/**
 * Check IPK is valid.
 */
func VerifyIPK(ipk *IPK) error {
	X := ipk.X
	Y := ipk.Y
	c := ipk.c
	sX := ipk.sX
	sY := ipk.sY

	// calc U_x = g2^s_x * X^{-c}
	Ux := g2().Mul(sX)
	tmp := X.Mul(c)
	Ux.Sub(tmp)

	// calc U_y = g2^s_y * Y^{-c}
	Uy := g2().Mul(sY)
	tmp = Y.Mul(c)
	Uy.Sub(tmp)

	// calc `c' = H(U_x | U_y | g2 | X | Y)`
	hash := NewHash()
	hash.WriteECP2(Ux, Uy, g2(), X, Y)
	cDash := hash.SumToBIG()

	if FP256BN.Comp(c, cDash) == 0 {
		return nil
	} else {
		return errors.New("IPK is not valid\n")
	}
}

type Issuer struct {
	ipk IPK
	isk ISK
}

func NewIssuer(isk ISK, ipk IPK) Issuer {
	var issuer Issuer
	issuer.isk = isk
	issuer.ipk = ipk

	return issuer
}

func RandomIssuer(rng *core.RAND) Issuer {
	isk := RandomISK(rng)
	ipk := RandomIPK(&isk, rng)

	issuer := NewIssuer(isk, ipk)

	return issuer
}
