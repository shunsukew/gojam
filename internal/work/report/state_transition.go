package workreport

import (
	"crypto/ed25519"

	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/entropy"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/pkg/common"
)

type PendingWorkReports [common.NumOfCores]*PendingWorkReport

type PendingWorkReport struct {
	ReportedAt jamtime.TimeSlot
	WorkReport *WorkReport
}

// This method should be called after disputes done, which means intermidiate state ρ†
func (p *PendingWorkReports) AssureAvailabilities(
	timeSlot jamtime.TimeSlot,
	assuances Assurances,
	parentHash common.Hash,
	currentValidators *[common.NumOfValidators]*keys.ValidatorKey, // K' posterior current validators keys set should come here.
) ([]*WorkReport, error) {
	// At this point, PendingWorkReports must be ρ† (intermidiate state after disputes).

	err := assuances.validate(p, parentHash, currentValidators)
	if err != nil {
		return nil, err
	}

	coreAvailabilityCounters := make(map[int]int, common.NumOfCores)
	for _, assurance := range assuances {
		for coreIndex, available := range assurance.WorkReportAvailabilities {
			if available {
				coreAvailabilityCounters[coreIndex] += 1
			}
		}
	}

	// TODO: Output available work reports contains stale ones as long as collecting super majoriry assurances.
	// Identify how stale work reports are handled later.
	availableReports := []*WorkReport{}
	for coreIndex, pendingWorkReport := range *p {
		if pendingWorkReport == nil {
			continue
		}

		// Super majority assurance check
		if count, ok := coreAvailabilityCounters[coreIndex]; ok && count >= common.NumOfSuperMajorityValidators {
			availableReports = append(availableReports, pendingWorkReport.WorkReport)
			(*p)[coreIndex] = nil // Remove the report as it is now available.
		}

		// Stale work report check
		if pendingWorkReport.ReportedAt+PendingWorkReportTimeout <= timeSlot {
			(*p)[coreIndex] = nil // Remove the report if it is too old.
			continue
		}
	}

	return availableReports, nil
}

func (p *PendingWorkReports) GuaranteeNewWorkReports(
	guarantees Guarantees,
	timeSlot jamtime.TimeSlot,
	entropyPool *entropy.EntropyPool, // entropy should be rotated before guaranteeing new work reports.
	currentGuarantors *[common.NumOfValidators]*keys.ValidatorKey, // K' posterior current validators keys set should come here.
	archivedGuarantors *[common.NumOfValidators]*keys.ValidatorKey, // λ' posterior archived validators keys set should come here.
) ([]*WorkReport, error) {
	// At this point, PendingWorkReports must be ρ†† (intermidiate state after availability assurances).

	if len(guarantees) > common.NumOfCores {
		return nil, ErrTooManyGuarantees
	}

	err := guarantees.validateCoreIndices()
	if err != nil {
		return nil, errors.WithMessagef(ErrInvalidGuarantees, "guarantees must be sorted and non-duplicate core indices")
	}

	// G together with currentGuarantors
	currentGuarantorAssignments := assignGuarantors(timeSlot, entropyPool[2]) // Use η2'
	// G* together with archivedGuarantors
	prevGuarantorAssignments := currentGuarantorAssignments
	if jamtime.TimeSlot(timeSlot-jamtime.GuarantorRotationPeriod).ToEpoch() != timeSlot.ToEpoch() {
		prevGuarantorAssignments = assignGuarantors(timeSlot-jamtime.GuarantorRotationPeriod, entropyPool[3]) // Use η3' for previous guarantor assignments
	}

	workReports := make([]*WorkReport, 0, len(guarantees))
	reporters := make([]ed25519.PublicKey, 0, len(guarantees)*MaxCredentialsInGuarantee)

	for _, guarantee := range guarantees {
		guarantorAssignments := currentGuarantorAssignments
		guarantorKeys := currentGuarantors
		if !timeSlot.InSameGuarantorRotationPeriod(guarantee.Timeslot) {
			guarantorAssignments = prevGuarantorAssignments
			guarantorKeys = archivedGuarantors
		}

		guarantors, err := guarantee.checkGuaranteedWorkReport(timeSlot, guarantorAssignments, guarantorKeys)
		if err != nil {
			return nil, errors.WithMessagef(ErrInvalidGuarantees, "guarantee validation failed: %v", err)
		}

		workReports = append(workReports, guarantee.WorkReport)
		reporters = append(reporters, guarantors...)
	}

	// TODO:

	return nil, nil
}
