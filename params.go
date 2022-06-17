package main

import "miracl/core/FP256BN"

const SEED_SIZE = 100

var pVal *FP256BN.BIG = nil

func p() *FP256BN.BIG {
	if pVal == nil {
		pVal = FP256BN.NewBIGints(FP256BN.CURVE_Order)
	}

	return pVal
}
