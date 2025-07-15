package schnorr

import (
	ml "github.com/IBM/mathlib"
	"golang.org/x/crypto/blake2b"
)

const frCompressedSize = 32 // size of field element in bytes

func SumOfG1Products(bases []*ml.G1, scalars []*ml.Zr) *ml.G1 {
	var res *ml.G1

	for i := 0; i < len(bases); i++ {
		b := bases[i]
		s := scalars[i]

		g := b.Mul(s.Copy())
		if res == nil {
			res = g
		} else {
			res.Add(g)
		}
	}

	return res
}

// return true if e(p1, q1) == e(p2, q2)
func CompareTwoPairings(curve *ml.Curve, p1 *ml.G1, q1 *ml.G2,
	p2 *ml.G1, q2 *ml.G2) bool {

	// DEVIATION FROM aries-bbs-go, so that this function can be used black-box
	p2Copy := p2.Copy()
	p2Copy.Neg()

	p := curve.Pairing2(q1, p1, q2, p2Copy)
	p = curve.FExp(p)

	return p.IsUnity()
}

func IsZero(c *ml.Curve, z *ml.Zr) bool {
	zero := c.NewZrFromBytes([]byte("0"))
	zero = zero.Minus(zero)
	return z.Equals(zero)
}

func NonceToFrBytes(curve *ml.Curve, nonce []byte) []byte {
	fieldElem := FrFromOKM(curve, nonce)
	return fieldElem.Bytes()
}

func FrFromOKM(c *ml.Curve, message []byte) *ml.Zr {
	const (
		eightBytes = 8
		okmMiddle  = 24
	)

	// We pass a null key so error is impossible here.
	h, _ := blake2b.New384(nil) //nolint:errcheck

	// blake2b.digest() does not return an error.
	_, _ = h.Write(message)
	okm := h.Sum(nil)
	emptyEightBytes := make([]byte, eightBytes)

	elm := c.NewZrFromBytes(append(emptyEightBytes, okm[:okmMiddle]...))

	f2192 := c.NewZrFromBytes([]byte{
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	})

	elm = elm.Mul(f2192)

	fr := c.NewZrFromBytes(append(emptyEightBytes, okm[okmMiddle:]...))
	elm = elm.Plus(fr)

	return elm
}
