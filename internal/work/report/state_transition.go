package workreport

import (
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
	validators *[common.NumOfValidators]*keys.ValidatorKey, // K' posterior current validators keys set should come here.
) ([]*WorkReport, error) {
	// At this point, PendingWorkReports must be ρ† (intermidiate state after disputes).

	err := assuances.validate(p, parentHash, validators)
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
