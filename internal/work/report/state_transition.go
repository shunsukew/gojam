package workreport

import (
	"crypto/ed25519"
	"fmt"

	"slices"

	"github.com/pkg/errors"
	authpool "github.com/shunsukew/gojam/internal/authorizer/pool"
	"github.com/shunsukew/gojam/internal/entropy"
	"github.com/shunsukew/gojam/internal/history"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/service"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/internal/work"
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
	authorizerPools *authpool.AuthorizerPools,
	services *service.Services,
	recentBlocks *history.RecentHistory,
) ([]*WorkReport, error) {
	// At this point, PendingWorkReports must be ρ†† (intermidiate state after availability assurances).

	fmt.Println("HERE Test!!!")

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

	workReports := make([]*WorkReport, len(guarantees))
	reporters := make([]ed25519.PublicKey, 0, len(guarantees)*MaxCredentialsInGuarantee)
	refinementContexts := make([]*work.RefinementContext, len(guarantees))
	workPackageHashes := make([]common.Hash, len(guarantees))
	seenWorkPackageHashes := make(map[common.Hash]struct{}, len(guarantees))

	for i, guarantee := range guarantees {
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

		workReports[i] = guarantee.WorkReport
		reporters = append(reporters, guarantors...)
		refinementContexts[i] = guarantee.WorkReport.RefinementContext
		workPackageHashes[i] = guarantee.WorkReport.AvailabilitySpecification.WorkPackageHash
		seenWorkPackageHashes[guarantee.WorkReport.AvailabilitySpecification.WorkPackageHash] = struct{}{}
	}

	// compare cardinality of work package hashes in guarantees extrinsic with the number of work reports.
	if len(seenWorkPackageHashes) != len(workReports) {
		return nil, errors.WithMessagef(ErrInvalidGuarantees, "work package hash must be unique in guarantees extrinsic")
	}

	// Check if work reports in corresponding cores are empty or work report exists but stale.
	for _, workReport := range workReports {
		// No reports may be placed on cores with a report pending availability on it.
		if p[workReport.CoreIndex] != nil {
			return nil, errors.WithMessagef(ErrInvalidWorkReport, "work report for core %d exists and waiting for availability assurances", workReport.CoreIndex)
		}

		// Check if authorizer hash is present in the authorizer pool of the core on which the work is reported.
		if !slices.Contains(authorizerPools[workReport.CoreIndex], workReport.AuthorizerHash) {
			return nil, errors.WithMessagef(ErrInvalidWorkReport, "work report authorizer hash in core %d doesn't exist in authorizer queue", workReport.CoreIndex)
		}

		// Check work report validity
		err = workReport.validateGasRequirements(services)
		if err != nil {
			return nil, err
		}
	}

	for _, rc := range refinementContexts {
		err = rc.ValidateAnchors(timeSlot, recentBlocks)
		if err != nil {
			return nil, err
		}
	}

	return nil, nil
}
