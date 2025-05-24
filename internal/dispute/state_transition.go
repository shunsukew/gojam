package dispute

import (
	"crypto/ed25519"

	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/pkg/common"
)

// TODO: Remove active validators and archived validators from Update method.
// effective validators Key set k should be determined before the dispute state transition.
func (ds *DisputeState) Update(
	verdicts Verdicts,
	culprits Culprits,
	faults Faults,
	activeValidators []*keys.ValidatorKey,
	archivedValidators []*keys.ValidatorKey,
	timeSlot jamtime.TimeSlot,
) error {
	if !verdicts.isSortedNonDuplicates() {
		return errors.WithMessagef(ErrInvalidVerdicts, "verdicts are not sorted or contain duplicates")
	}

	if !culprits.isSortedNonDuplicates() {
		return errors.WithMessagef(ErrInvalidCulprits, "culprits are not sorted or contain duplicates")
	}

	if !faults.isSortedNonDuplicates() {
		return errors.WithMessagef(ErrInvalidFaults, "faults are not sorted or contain duplicates")
	}

	if reported, reportHash := ds.containsPastReportHashes(verdicts); reported {
		return errors.WithMessagef(ErrInvalidVerdicts, "verdicts have already been reported in the past: %s", reportHash)
	}

	calpritsSet := map[common.Hash][]ed25519.PrivateKey{}
	for _, c := range culprits {
		calpritsSet[c.WorkReportHash] = append(calpritsSet[c.WorkReportHash], ed25519.PrivateKey(c.CulpritKey))
	}
	faultsSet := map[common.Hash][]ed25519.PrivateKey{}
	for _, f := range faults {
		faultsSet[f.WorkReportHash] = append(faultsSet[f.WorkReportHash], ed25519.PrivateKey(f.FaultKey))
	}

	for _, v := range verdicts {
		if v.Judgements.isSortedNonDuplicates() {
			return errors.WithMessagef(ErrInvalidVerdicts, "judgements in verdict %s are not sorted or contain duplicates", v.WorkReportHash)
		}

		verdictOutcome, err := v.TallyVotes()
		if err != nil {
			return errors.WithMessagef(ErrInvalidVerdicts, "failed to tally votes for verdict %s: %v", v.WorkReportHash, err)
		}

		switch verdictOutcome.Conclusion {
		case GoodReport:
			// Faults should contain at least one valid entry.
			if len(faultsSet[verdictOutcome.WorkReportHash]) < 1 {
				return errors.WithMessagef(ErrInvalidFaults, "no valid faults for good report %s", verdictOutcome.WorkReportHash)
			}
		case BadReport:
			// Culprits should contain at least two valid entries.
			if len(calpritsSet[verdictOutcome.WorkReportHash]) < 2 {
				return errors.WithMessagef(ErrInvalidCulprits, "not enough valid culprits for bad report %s", verdictOutcome.WorkReportHash)
			}
		default:
		}
	}

	return nil
}
