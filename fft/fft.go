package fft

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
)

type Poly struct {
	repr   []fr.Element
	degree int
}

func FFT(p Poly) {
	// TODO make sure that the domain is correct even if we don't have a power of 2
	domain := fft.NewDomain(uint64(p.degree))

	domain.FFT(p.repr, fft.DIT)
	// domain.FFT(p.repr, fft.DIT, fft.OnCoset())
}
