package bandersnatch

import (
	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/pkg/common"
)

const (
	PrivateKeySize     = 32
	PublicKeySize      = 32
	RingCommitmentSize = 144
	SignatureSize      = 784
	VrfOutputSize      = 32
)

type PrivateKey [32]byte

type PublicKey [PublicKeySize]byte

type RingCommitment [RingCommitmentSize]byte

func NewRingCommitment(pubkeys []PublicKey) (RingCommitment, error) {
	if len(pubkeys) != common.NumOfValidators {
		return RingCommitment{}, errors.New("invalid number of public keys")
	}

	return newRingCommitment(pubkeys)
}

type Signature [784]byte

func (proof Signature) Verify(input, auxData []byte, ringCommitment RingCommitment) (VrfOutput, error) {
	output, err := verify(input, auxData, ringCommitment, proof)
	if err != nil {
		return VrfOutput{}, errors.WithStack(err)
	}

	return output, nil
}

type VrfOutput [VrfOutputSize]byte
