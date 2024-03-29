package ecdaa

import (
	"fmt"

	"github.com/akakou-fork/amcl-go/miracl/core"
	"github.com/akakou-fork/amcl-go/miracl/core/FP256BN"
	amcl_utils "github.com/akakou/fp256bn-amcl-utils"
)

/**
 * ISK: Issuer's Secret Key.
 */
type ISK struct {
	X *FP256BN.BIG
	Y *FP256BN.BIG
}

/**
 * Generate IPK with random.
 */
func RandomISK(rng *core.RAND) ISK {
	var isk ISK
	x := FP256BN.Random(rng)
	y := FP256BN.Random(rng)

	x.Mod(amcl_utils.P())
	y.Mod(amcl_utils.P())

	isk.X = x
	isk.Y = y

	return isk
}

/**
 * IPL: Issuer's Public Key.
 */
type IPK struct {
	X  *FP256BN.ECP2
	Y  *FP256BN.ECP2
	C  *FP256BN.BIG
	SX *FP256BN.BIG
	SY *FP256BN.BIG
}

/**
 * Generate IPK with random and ISK.
 */
func RandomIPK(isk *ISK, rng *core.RAND) IPK {
	// random r_x, r_y
	var ipk IPK

	x := isk.X
	y := isk.Y

	rX := FP256BN.Random(rng)
	rY := FP256BN.Random(rng)

	rX.Mod(amcl_utils.P())
	rY.Mod(amcl_utils.P())

	// calc X, Y
	// X = g2^x
	// Y = g2^y
	X := amcl_utils.G2().Mul(x)
	Y := amcl_utils.G2().Mul(y)

	// calc U_x, U_y
	//     U_x = g2 ^ r_x
	//     U_y = g2 ^ r_y
	Ux := amcl_utils.G2().Mul(rX)
	Uy := amcl_utils.G2().Mul(rY)

	// calc `c = H(U_x | U_y | g2 | X | Y)`
	hash := amcl_utils.NewHash()
	hash.WriteECP2(Ux, Uy, amcl_utils.G2(), X, Y)
	c := hash.SumToBIG()

	// calc s_x, s_y
	//     s_x = r_x + cx
	//     s_y = r_y + cy
	// todo: mod p
	sX := FP256BN.Modmul(c, x, amcl_utils.P())
	sX = FP256BN.Modadd(rX, sX, amcl_utils.P())

	sY := FP256BN.Modmul(y, c, amcl_utils.P())
	sY = FP256BN.Modadd(rY, sY, amcl_utils.P())

	// copy pointers to ipk
	ipk.X = X
	ipk.Y = Y
	ipk.C = c
	ipk.SX = sX
	ipk.SY = sY

	return ipk
}

/**
 * Check IPK is valid.
 */
func VerifyIPK(ipk *IPK) error {
	X := ipk.X
	Y := ipk.Y
	c := ipk.C
	sX := ipk.SX
	sY := ipk.SY

	// calc U_x = g2^s_x * X^{-c}
	Ux := amcl_utils.G2().Mul(sX)
	tmp := X.Mul(c)
	Ux.Sub(tmp)

	// calc U_y = g2^s_y * Y^{-c}
	Uy := amcl_utils.G2().Mul(sY)
	tmp = Y.Mul(c)
	Uy.Sub(tmp)

	// calc `c' = H(U_x | U_y | g2 | X | Y)`
	hash := amcl_utils.NewHash()
	hash.WriteECP2(Ux, Uy, amcl_utils.G2(), X, Y)
	cDash := hash.SumToBIG()

	if FP256BN.Comp(c, cDash) == 0 {
		return nil
	} else {
		return fmt.Errorf("IPK is not valid\n")
	}
}

type Issuer struct {
	Ipk IPK
	Isk ISK
}

func NewIssuer(isk ISK, ipk IPK) Issuer {
	var issuer Issuer
	issuer.Isk = isk
	issuer.Ipk = ipk

	return issuer
}

func RandomIssuer(rng *core.RAND) Issuer {
	isk := RandomISK(rng)
	ipk := RandomIPK(&isk, rng)

	issuer := NewIssuer(isk, ipk)

	return issuer
}
