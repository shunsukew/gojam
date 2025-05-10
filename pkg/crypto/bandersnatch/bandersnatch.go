package bandersnatch

import (
	"encoding/json"

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

func (pk *PrivateKey) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	bytes := common.FromHex(s)
	if len(bytes) != PrivateKeySize {
		return errors.New("invalid bandersnatch private key length")
	}

	copy(pk[:], bytes)

	return nil
}

type PublicKey [PublicKeySize]byte

func (pk *PublicKey) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	bytes := common.FromHex(s)
	if len(bytes) != PublicKeySize {
		return errors.New("invalid bandersnatch public key length")
	}
	copy(pk[:], bytes)

	return nil
}

type RingCommitment [RingCommitmentSize]byte

func (rc *RingCommitment) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	bytes := common.FromHex(s)
	if len(bytes) != RingCommitmentSize {
		return errors.New("invalid bandersnatch ring commitment length")
	}

	copy(rc[:], bytes)

	return nil
}

func NewRingCommitment(pubkeys []PublicKey) (*RingCommitment, error) {
	if len(pubkeys) != common.NumOfValidators {
		return &RingCommitment{}, errors.New("invalid number of public keys")
	}

	return newRingCommitment(pubkeys)
}

type Signature [784]byte

func (proof Signature) Verify(input, auxData []byte, ringCommitment *RingCommitment) (VrfOutput, error) {
	output, err := verify(input, auxData, ringCommitment, proof)
	if err != nil {
		return VrfOutput{}, err
	}

	return output, nil
}

func (sig *Signature) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	bytes := common.FromHex(s)
	if len(bytes) != SignatureSize {
		return errors.New("invalid bandersnatch signature length")
	}
	copy(sig[:], bytes)

	return nil
}

type VrfOutput [VrfOutputSize]byte

func (vo *VrfOutput) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	bytes := common.FromHex(s)
	if len(bytes) != VrfOutputSize {
		return errors.New("invalid bandersnatch vrf output length")
	}

	copy(vo[:], bytes)

	return nil
}
