package main

import "miracl/core/FP256BN"

/**
 * Random seed size
 */
const SEED_SIZE = 100

var pVal *FP256BN.BIG = nil

/**
 * The order of this curve.
 *
 * The big numbers used in this library,
 * all values are taken reminder of this p.
 */
func p() *FP256BN.BIG {
	if pVal == nil {
		pVal = FP256BN.NewBIGints(FP256BN.CURVE_Order)
	}

	return pVal
}

func g1() *FP256BN.ECP {
	return FP256BN.ECP_generator()
}

func g2() *FP256BN.ECP2 {
	return FP256BN.ECP2_generator()
}

func zero() *FP256BN.BIG {
	return FP256BN.NewBIGint(0)
}
