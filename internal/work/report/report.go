package workreport

import (
	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/service"
	"github.com/shunsukew/gojam/internal/work"
	"github.com/shunsukew/gojam/pkg/common"
)

const (
	OutOfGas           ExecError = iota // ∞
	Panic              ExecError = iota // ☇
	ReportInvalid      ExecError = iota // ⊚
	ServiceUnavailable ExecError = iota // BAD
	CodeTooBig         ExecError = iota // BIG
)

type WorkReports []*WorkReport

func (wr *WorkReports) ensureDependenciesExist(recentWorkPackageHashes map[common.Hash]struct{}) error {
	dependencies := wr.extractDependencyWorkPackageHashes()

	for dep := range dependencies {
		if _, ok := recentWorkPackageHashes[dep]; !ok {
			return errors.WithMessagef(ErrInvalidWorkReport, "dependency work package hash %s does not exist in recent work packages", dep)
		}
	}

	return nil
}

// TODO: Convert output to map of work report hash to dependency work package hashes, so that we can know which work report has invalid dependencies in error msg and logging.
func (wr *WorkReports) extractDependencyWorkPackageHashes() map[common.Hash]struct{} {
	workPackageHashes := make(map[common.Hash]struct{})
	for _, report := range *wr {
		for _, preRequisiteWorkPackageHash := range report.RefinementContext.PreRequisiteWorkPackageHashes {
			workPackageHashes[preRequisiteWorkPackageHash] = struct{}{}
		}

		for workPackageHash := range report.SegmentRootLookup {
			workPackageHashes[workPackageHash] = struct{}{}
		}
	}

	return workPackageHashes
}

func (wr *WorkReports) ensureSegmentRoots(recentSegmentRootLookups map[common.Hash]common.Hash) error {
	for _, report := range *wr {
		// check map report.SegmentRootLookup map[common.Hash]common.Hash all key-val paris exists in recentSegmentRootLookups
		for workPackageHash, expected := range report.SegmentRootLookup {
			actual, ok := recentSegmentRootLookups[workPackageHash]
			if !ok {
				return errors.WithMessagef(ErrInvalidWorkReport, "missing segment root for work package hash %s", workPackageHash)
			}
			if actual != expected {
				return errors.WithMessagef(ErrInvalidWorkReport, "segment root for work package hash %s does not match: expected %s, got %s", workPackageHash, expected, actual)
			}
		}
	}

	return nil
}

// (11.2) W ≡ (s ∈ S, x ∈ X, c ∈ NC, a ∈ H, o ∈ Y, l ∈ D⟨H→H⟩, r ∈ ⟦L⟧1:I)
type WorkReport struct {
	AvailabilitySpecification *AvailabilitySpecification  // s ∈ S
	RefinementContext         *work.RefinementContext     // x ∈ X
	CoreIndex                 uint32                      // c ∈ NC
	AuthorizerHash            common.Hash                 // a ∈ H
	Output                    []byte                      // o ∈ Y
	SegmentRootLookup         map[common.Hash]common.Hash // l ∈ D⟨H→H⟩ work package hash to segment root
	WorkResults               []*WorkResult               // r ∈ ⟦L⟧1:I cannot be empty
}

// (11.5) S ≡ [ h ∈ H, l ∈ NL, u ∈ H, e ∈ H, n ∈ N ]
type AvailabilitySpecification struct {
	WorkPackageHash  common.Hash // h ∈ H
	WorkBundleLength uint32      // l ∈ NL
	ErasureRoot      common.Hash // u ∈ H
	SegmentRoot      common.Hash // e ∈ H
	SegmentCount     uint        // n ∈ N
}

// (11.6) L ≡ (s ∈ NS , c ∈ H, l ∈ H, g ∈ NG , o ∈ Y ∪ J)
type WorkResult struct {
	ServiceId       service.ServiceId // s ∈ NS
	ServiceCodeHash common.Hash       // c ∈ H
	PayloadHash     common.Hash       // l ∈ H
	Gas             service.Gas       // g ∈ NG
	ExecResult      *ExecResult       // o ∈ Y ∪ J
}

type ExecError int

type ExecResult struct {
	Output []byte    // Y
	Error  ExecError // J ∈ {∞, ☇, ⊚, BAD, BIG}
}

func (wr *WorkReport) validateGasRequirements(services *service.Services) error {
	totalGas := service.Gas(0)
	for _, workResult := range wr.WorkResults {
		service, ok := services.Get(workResult.ServiceId)
		if !ok {
			return errors.WithMessagef(ErrInvalidWorkReport, "service %d not found", workResult.ServiceId)
		}

		// each work result gas must be greater than or equal to the service's minimum accumulate gas requirement
		if workResult.Gas < service.AccumulateGas {
			return errors.WithMessagef(
				ErrInvalidWorkReport, "work result gas %d doesn't satisfy service accumulate minimum gas requirement %d of id %d",
				workResult.Gas, service.AccumulateGas, workResult.ServiceId,
			)
		}

		totalGas += workResult.Gas
	}

	// overall work report gas must be lower than G_A
	if totalGas > service.WorkReportAccumulationGasLimit {
		return errors.WithMessagef(
			ErrInvalidWorkReport,
			"total gas %d of work report exceeds the work report accumulation gas limit %d",
			totalGas, service.WorkReportAccumulationGasLimit,
		)
	}

	return nil
}

func (wr *WorkReport) validateWorkResults(services *service.Services) error {
	for _, workResult := range wr.WorkResults {
		service, ok := services.Get(workResult.ServiceId)
		if !ok {
			return errors.WithMessagef(ErrInvalidWorkReport, "work result service %d not found", workResult.ServiceId)
		}

		if workResult.ServiceCodeHash != service.CodeHash {
			return errors.WithMessagef(ErrInvalidWorkReport, "work result service code hash %s does not match service code hash %s for service %d",
				workResult.ServiceCodeHash, service.CodeHash, workResult.ServiceId)
		}
	}

	return nil
}
