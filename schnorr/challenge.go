package schnorr

import ml "github.com/IBM/mathlib"

type ChallengeProvider interface {
	GetChallenge() *ml.Zr
}

type GenericChallProvider struct {
	curve      *ml.Curve
	commitment *ml.G1
	bases      []*ml.G1
	nonce      []byte
}

func NewChallProvider(curve *ml.Curve, commitment *ml.G1, bases []*ml.G1, nonce []byte) *GenericChallProvider {
	return &GenericChallProvider{
		curve:      curve,
		commitment: commitment,
		bases:      bases,
		nonce:      nonce,
	}
}

func (p *GenericChallProvider) GetChallenge() *ml.Zr {
	challengeBytes := make([]byte, 0)
	// add bytes for every base
	for _, base := range p.bases {
		challengeBytes = append(challengeBytes, base.Bytes()...)
	}
	// add bytes for commitment
	challengeBytes = append(challengeBytes, p.commitment.Bytes()...)
	// add bytes for nonce
	challengeBytes = append(challengeBytes, NonceToFrBytes(p.curve, p.nonce)...)
	// convert final challenge bytes to a field element
	challenge := FrFromOKM(p.curve, challengeBytes)
	return challenge
}
