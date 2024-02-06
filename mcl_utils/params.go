package mcl_utils

import "github.com/akakou-fork/amcl-go/miracl/core/FP256BN"

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
func P() *FP256BN.BIG {
	if pVal == nil {
		pVal = FP256BN.NewBIGints(FP256BN.CURVE_Order)
	}

	return pVal
}

func G1() *FP256BN.ECP {
	return FP256BN.ECP_generator()
}

func G2() *FP256BN.ECP2 {
	return FP256BN.ECP2_generator()
}
