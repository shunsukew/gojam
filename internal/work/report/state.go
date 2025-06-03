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
	assuances []*Assurance,
	parentHash common.Hash,
	validators *[common.NumOfValidators]*keys.ValidatorKey, // K' posterior current validators keys set should come here.
) error {
	// At this point, PendingWorkReports must be ρ† (intermidiate state after disputes).

	err := Assuances(assuances).validate(p, parentHash, validators)
	if err != nil {
		return err
	}

	// TODO: Output ρ††

	return nil
}
