package workreport

import (
	"crypto/ed25519"

	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/shuffle"
)

type Guarantees []*Guarantee

func (guarantees Guarantees) validateCoreIndices() error {
	for i := 1; i < len(guarantees); i++ {
		if guarantees[i].WorkReport.CoreIndex >= common.NumOfCores {
			return errors.WithMessage(ErrInvalidGuarantees, "core index out of range")
		}
		if guarantees[i].WorkReport.CoreIndex <= guarantees[i-1].WorkReport.CoreIndex {
			return errors.WithMessage(ErrInvalidGuarantees, "guarantees must be ordered by core index and unique")
		}
	}
	return nil
}

// (w ∈ W, t ∈ NT, a ∈ ⟦(NV, E)⟧₂:₃)
type Guarantee struct {
	WorkReport  *WorkReport      // w ∈ W
	Timeslot    jamtime.TimeSlot // t ∈ NT
	Credentials []*Credential    // TODO: array length must be 2 or 3 (2:3). unique per validator index, order by validator index (11.25) ∀g ∈ EG ∶ ga = [v || (v,s) ∈ ga].
}

type Credential struct {
	ValidatorIndex uint32
	Signature      []byte // 𝔼
}

func (guarantee *Guarantee) checkGuaranteedWorkReport(timeSlot jamtime.TimeSlot, guarantorAssignments *GuarantorAssignments, guarantorKeys *[common.NumOfValidators]*keys.ValidatorKey) ([]ed25519.PublicKey, error) {
	// guarantee timeslot must be between start of prev guarantor assignment rotation period and current timeslot.
	startOfPrevRotationPeriod := (timeSlot/jamtime.GuarantorRotationPeriod - 1) * jamtime.GuarantorRotationPeriod
	if timeSlot.Before(startOfPrevRotationPeriod) {
		return nil, errors.WithMessagef(ErrInvalidGuarantee, "guarantee timeslot %d is before the start of previous guarantor rotation period %d", guarantee.Timeslot, startOfPrevRotationPeriod)
	}
	if guarantee.Timeslot.After(timeSlot) {
		return nil, errors.WithMessagef(ErrInvalidGuarantee, "guarantee timeslot %d is after current timeslot %d", guarantee.Timeslot, timeSlot)
	}

	// credentials are array of length 2 or 3 defined gray paper
	if len(guarantee.Credentials) != 2 && len(guarantee.Credentials) != 3 {
		return nil, errors.WithMessagef(ErrInvalidGuarantee, "invalid number of credentials: %d, must be 2 or 3", len(guarantee.Credentials))
	}

	// Check credentials are ordered by validator index
	for i := 1; i < len(guarantee.Credentials); i++ {
		if guarantee.Credentials[i].ValidatorIndex <= guarantee.Credentials[i-1].ValidatorIndex {
			return nil, errors.WithMessage(ErrInvalidGuarantee, "credentials must be ordered by validator index")
		}
	}

	reporters := make([]ed25519.PublicKey, 0, MaxCredentialsInGuarantee)
	for _, credential := range guarantee.Credentials {
		if credential.ValidatorIndex >= common.NumOfValidators {
			return nil, errors.WithMessagef(ErrInvalidGuarantee, "validator index in credential is out of range %d", credential.ValidatorIndex)
		}

		// Core index must be correct.
		if guarantee.WorkReport.CoreIndex != guarantorAssignments[credential.ValidatorIndex] {
			return nil, errors.WithMessagef(
				ErrInvalidCredential,
				"credential from validator index %d is associated to work report of core index %d, but should be assigned core index %d",
				credential.ValidatorIndex,
				guarantee.WorkReport.CoreIndex,
				guarantorAssignments[credential.ValidatorIndex],
			)
		}

		// TODO: Check signature
		// 1. encode work report
		// 2. concat with statement and hash
		// 3. verify signature with validator public key

		reporters = append(reporters, guarantorKeys[credential.ValidatorIndex].Ed25519PublicKey)
	}

	return reporters, nil
}

type GuarantorAssignments [common.NumOfValidators]uint32

func assignGuarantors(timeSlot jamtime.TimeSlot, entropy common.Hash) *GuarantorAssignments {
	guarantorAssignments := GuarantorAssignments(permuteAssignedCoreIndices(timeSlot, entropy))
	return &guarantorAssignments
}

// permute function P in gray paper.
func permuteAssignedCoreIndices(timeSlot jamtime.TimeSlot, entropy common.Hash) [common.NumOfValidators]uint32 {
	coreIndicies := [common.NumOfValidators]uint32{}
	for i := range common.NumOfValidators {
		coreIndicies[i] = uint32(common.NumOfCores * i / common.NumOfValidators)
	}

	shuffle.Shuffle(coreIndicies[:], entropy)

	rotate(&coreIndicies, uint32(timeSlot.ToTimeSlotInEpoch()/jamtime.GuarantorRotationPeriod))

	return coreIndicies
}

// rotate function R in gray paper.
func rotate(coreIndicies *[common.NumOfValidators]uint32, shift uint32) {
	for i := range len(coreIndicies) {
		coreIndicies[i] = (coreIndicies[i] + shift) % common.NumOfCores
	}
}
