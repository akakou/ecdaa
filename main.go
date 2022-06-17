package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"miracl/core"
	"miracl/core/FP256BN"
)

const SEED_SIZE = 100

var pVal *FP256BN.BIG = nil

type ISK struct {
	x *FP256BN.BIG
	y *FP256BN.BIG
}

func HashECP2s(n ...*FP256BN.ECP2) *FP256BN.BIG {
	hasher := sha256.New()
	var buf [2*int(FP256BN.MODBYTES) + 1]byte

	for _, v := range n {
		v.ToBytes(buf[:], true)
		hasher.Write(buf[:])
	}

	retHash := hasher.Sum(nil)
	resBIG := FP256BN.FromBytes(retHash)

	return resBIG
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

func p() *FP256BN.BIG {
	if pVal == nil {
		pVal = FP256BN.NewBIGints(FP256BN.CURVE_Order)
	}

	return pVal
}

func RandomIPK(isk *ISK, rng *core.RAND) IPK {
	// random r_x, r_y
	var ipk IPK

	x := isk.x
	y := isk.y

	r_x := FP256BN.Random(rng)
	r_y := FP256BN.Random(rng)

	// calc X, Y, U_x, U_y
	X := FP256BN.ECP2_generator().Mul(x)
	Y := FP256BN.ECP2_generator().Mul(y)

	// U_x := FP256BN.ECP2_generator().Mul(r_x)
	// U_y := FP256BN.ECP2_generator().Mul(r_y)

	// calc `c = H(U_x | U_y | X | Y)`

	c := HashECP2s(X, Y)

	// c := new(big.Int).SetBytes(buf)

	// calc s_x, s_y
	//     s_x = r_x + cx
	//     s_y = r_y + cy
	// todo: mod p
	s_x := FP256BN.NewBIG()
	s_x = FP256BN.Modmul(x, c, p())
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

	invC := FP256BN.NewBIGcopy(c)
	invC.Invmodp(p())

	tmpX1 := FP256BN.ECP2_generator().Mul(s_x)
	tmpX2 := X.Mul(invC)
	tmpX1.Add(tmpX2)

	// tmpX := tmpX1

	tmpY1 := FP256BN.ECP2_generator().Mul(s_y)
	tmpY2 := Y.Mul(invC)
	tmpY1.Add(tmpY2)

	// tmpY := tmpY1

	cDash := HashECP2s(X, Y)

	if FP256BN.Comp(c, cDash) == 0 {
		return nil
	} else {
		return errors.New("err: IPK is not valid\n")
	}
}

func InitRandom() *core.RAND {
	var seed [SEED_SIZE]byte
	rng := core.NewRAND()

	for i := 0; i < SEED_SIZE; i++ {
		s, _ := rand.Int(rand.Reader, big.NewInt(256))
		seed[i] = byte(s.Int64())
	}

	rng.Seed(SEED_SIZE, seed[:])

	return rng

}

func main() {
	rng := InitRandom()
	isk := RandomISK(rng)

	ipk := RandomIPK(&isk, rng)

	fmt.Println("x: %v", isk.x)
	fmt.Println("y: %v", isk.y)

	fmt.Println("X: %v", ipk.X)
	fmt.Println("Y: %v", ipk.Y)
	fmt.Println("c: %v", ipk.c)
	fmt.Println("s_x: %v", ipk.s_x)
	fmt.Println("s_y: %v", ipk.s_y)

	err := VerifyIPK(&ipk)
	fmt.Printf("err: %v", err)
}
