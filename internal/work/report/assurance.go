package workreport

import (
	"crypto/ed25519"

	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/pkg/codec"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto"
	"golang.org/x/crypto/blake2b"
)

type Assurances []*Assurance

type Assurance struct {
	AnchorParentHash         common.Hash             // Anchor of the assurance
	WorkReportAvailabilities [common.NumOfCores]bool // bitstring of work report availability assurances, one bit per core
	ValidatorIndex           uint32                  // Index of the validator in the assurance
	Signature                []byte                  // Signature of the validator ed25519 key
}

func (assurances Assurances) validate(
	pendingWorkReports *PendingWorkReports,
	parentHash common.Hash,
	validators *[common.NumOfValidators]*keys.ValidatorKey,
) error {
	if len(assurances) > common.NumOfValidators {
		return errors.WithMessagef(
			ErrInvalidAssuance,
			"too many assurances: %d, must be less than or equal to num of validators %d",
			len(assurances),
			common.NumOfValidators,
		)
	}

	if len(assurances) == 0 {
		return nil
	}

	err := (assurances)[0].validate(pendingWorkReports, parentHash, validators)
	if err != nil {
		return errors.WithStack(err)
	}

	for i := 1; i < len(assurances); i++ {
		if (assurances)[i].ValidatorIndex <= (assurances)[i-1].ValidatorIndex {
			return errors.WithMessagef(ErrInvalidAssuance, "assurance validator index is out of order")
		}
		err = (assurances)[i].validate(pendingWorkReports, parentHash, validators)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func (assurance *Assurance) validate(
	pendingWorkReports *PendingWorkReports,
	parentHash common.Hash,
	validators *[common.NumOfValidators]*keys.ValidatorKey,
) error {
	if assurance.AnchorParentHash != parentHash {
		return errors.WithMessagef(
			ErrInvalidAssuance,
			"anchor parent hash of assurance from validator %d mismatch: expected %s, got %s",
			assurance.ValidatorIndex,
			parentHash,
			assurance.AnchorParentHash,
		)
	}

	if assurance.ValidatorIndex >= common.NumOfValidators {
		return errors.WithMessagef(
			ErrInvalidAssuance,
			"assurance validator index %d is out of bounds, must be less than %d",
			assurance.ValidatorIndex,
			common.NumOfValidators,
		)
	}

	if !verifyAssuranceSignature(
		parentHash,
		assurance.WorkReportAvailabilities,
		validators[assurance.ValidatorIndex].Ed25519PublicKey,
		assurance.Signature,
	) {
		return errors.WithMessagef(
			ErrInvalidAssuance,
			"assurance signature verification failed for validator %d",
			assurance.ValidatorIndex,
		)
	}

	for coreIndex := range common.NumOfCores {
		assured := assurance.WorkReportAvailabilities[coreIndex]
		if assured && pendingWorkReports[coreIndex] == nil {
			return errors.WithMessagef(
				ErrInvalidAssuance,
				"assurance for core %d from validator %s marked the pending work report available, but pending work report is nil",
				coreIndex,
				common.Bytes2Hex(validators[assurance.ValidatorIndex].Ed25519PublicKey),
			)
		}
	}

	return nil
}

func verifyAssuranceSignature(
	parentHash common.Hash,
	workReportAvailabilities [common.NumOfCores]bool,
	publicKey ed25519.PublicKey,
	signature []byte,
) bool {
	encoded := codec.EncodeBitSequence(workReportAvailabilities[:])
	inputHash := blake2b.Sum256(append(parentHash[:], encoded...))
	msg := append([]byte(crypto.JamAssuranceStatement), inputHash[:]...)
	return ed25519.Verify(publicKey, msg, signature)
}

func EncodeBits(bits []bool) []byte {
	if len(bits) == 0 {
		return []byte{}
	}

	numBytes := (len(bits) + 7) / 8
	encoded := make([]byte, numBytes)

	for i, bit := range bits {
		if bit {
			byteIndex := i / 8
			bitPosition := i % 8 // LSB-first
			encoded[byteIndex] |= 1 << bitPosition
		}
	}

	return encoded
}
