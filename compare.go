package main

import "miracl/core/FP256BN"

func compECP(x FP256BN.ECP, y FP256BN.ECP) bool {
	x.Affine()
	y.Affine()

	xX := x.GetX()
	xY := x.GetY()

	yX := y.GetX()
	yY := y.GetY()

	return FP256BN.Comp(xX, xY) == 0 && FP256BN.Comp(yX, yY) == 0
}
