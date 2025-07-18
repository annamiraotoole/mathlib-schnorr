package schnorr

import ml "github.com/IBM/mathlib"

type CommitmentBuilder struct {
	bases   []*ml.G1
	scalars []*ml.Zr
}

func NewCommitmentBuilder(expectedSize int) *CommitmentBuilder {
	return &CommitmentBuilder{
		bases:   make([]*ml.G1, 0, expectedSize),
		scalars: make([]*ml.Zr, 0, expectedSize),
	}
}

func (cb *CommitmentBuilder) Add(base *ml.G1, scalar *ml.Zr) {
	cb.bases = append(cb.bases, base)
	cb.scalars = append(cb.scalars, scalar)
}

func (cb *CommitmentBuilder) Build() *ml.G1 {
	return SumOfG1Products(cb.bases, cb.scalars)
}
