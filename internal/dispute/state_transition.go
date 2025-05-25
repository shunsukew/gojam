package dispute

import (
	"crypto/ed25519"

	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto"
)

const (
	GoodReportLabel   ReportLabel = "good"
	BadReportLabel    ReportLabel = "bad"
	WonkeyReportLabel ReportLabel = "wonkey"
)

type ReportLabel string

type VerdictSummary struct {
	WorkReportHash common.Hash
	Epoch          jamtime.Epoch
	PositiveVotes  int
	ReportLabel    ReportLabel
}

func (ds *DisputeState) SummarizeVerdicts(
	epoch jamtime.Epoch,
	verdicts Verdicts,
	activeValidators, archivedValidators []*keys.ValidatorKey,
) (map[common.Hash]*VerdictSummary, error) {
	verdictSummaries := make(map[common.Hash]*VerdictSummary, len(verdicts))
	pastReported := ds.getPastWorkReports()

	for _, v := range verdicts {
		// work report hash should not be included if it has been reported in the past
		if _, exists := pastReported[v.WorkReportHash]; exists {
			return nil, errors.WithMessagef(ErrInvalidVerdicts, "verdict %s has already been reported in the past", v.WorkReportHash.ToHex())
		}

		if !v.Judgements.isSortedNonDuplicates() {
			return nil, errors.WithMessagef(ErrInvalidVerdicts, "judgements in verdict %s are not sorted or contain duplicates", v.WorkReportHash.ToHex())
		}

		var effectiveValidators []*keys.ValidatorKey
		if epoch.Equal(v.Epoch) {
			effectiveValidators = activeValidators
		} else if epoch.IsNextEpochAfter(v.Epoch) {
			effectiveValidators = archivedValidators
		} else {
			return nil, errors.WithMessagef(ErrInvalidVerdicts, "verdict %s has an invalid epoch: %d, expected %d or %d", v.WorkReportHash.ToHex(), v.Epoch, epoch, epoch+1)
		}

		for _, j := range v.Judgements {
			pubKey := effectiveValidators[j.ValidatorIndex].Ed25519PublicKey
			var msg []byte
			if j.Vote {
				msg = append([]byte(crypto.JamValidJudgementStatement), v.WorkReportHash[:]...)
			} else {
				msg = append([]byte(crypto.JamInvalidJudgementStatement), v.WorkReportHash[:]...)
			}
			if !ed25519.Verify(pubKey, msg, j.Signature) {
				return nil, errors.WithMessagef(ErrInvalidVerdicts, "verdict %s has an invalid cryptonature from validator %d", v.WorkReportHash.ToHex(), j.ValidatorIndex)
			}
		}

		summary, err := v.TallyVotes()
		if err != nil {
			return nil, errors.WithMessagef(ErrInvalidVerdicts, "failed to tally votes for verdict %s: %v", v.WorkReportHash, err)
		}

		verdictSummaries[v.WorkReportHash] = summary
	}

	return verdictSummaries, nil
}

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
	epoch := timeSlot.ToEpoch()

	activeValidatorsSet := make(map[string]struct{}, len(activeValidators))
	for _, v := range activeValidators {
		activeValidatorsSet[string(v.Ed25519PublicKey)] = struct{}{}
	}
	archivedValidatorsSet := make(map[string]struct{}, len(archivedValidators))
	for _, v := range archivedValidators {
		archivedValidatorsSet[string(v.Ed25519PublicKey)] = struct{}{}
	}

	if !verdicts.isSortedNonDuplicates() {
		return errors.WithMessage(ErrInvalidVerdicts, "verdicts are not sorted or contain duplicates")
	}

	// What if extrinsic contains same validator key in culprits and faults??

	if !culprits.isSortedNonDuplicates() {
		return errors.WithMessage(ErrInvalidCulprits, "culprits are not sorted or contain duplicates")
	}

	if !faults.isSortedNonDuplicates() {
		return errors.WithMessage(ErrInvalidFaults, "faults are not sorted or contain duplicates")
	}

	verdictSummaries, err := ds.SummarizeVerdicts(epoch, verdicts, activeValidators, archivedValidators)
	if err != nil {
		return errors.WithMessage(ErrInvalidVerdicts, err.Error())
	}

	offenders := make([]ed25519.PublicKey, 0, len(culprits)+len(faults))

	calpritsByReportHash := map[common.Hash][]*Culprit{}
	for _, c := range culprits {
		if _, ok := verdictSummaries[c.WorkReportHash]; !ok {
			return errors.WithMessagef(ErrInvalidCulprits, "culprit %s does not match any report hash in verdicts", c.WorkReportHash)
		}

		msg := append([]byte(crypto.JamGuaranteeStatement), c.WorkReportHash[:]...)
		if !ed25519.Verify(c.CulpritKey, msg, c.Signature) {
			return errors.WithMessagef(ErrInvalidCulprits, "culprit %s has an invalid signature", c.WorkReportHash)
		}

		calpritsByReportHash[c.WorkReportHash] = append(calpritsByReportHash[c.WorkReportHash], c)
		offenders = append(offenders, ed25519.PublicKey(c.CulpritKey))
	}

	faultsByReportHash := map[common.Hash][]*Fault{}
	for _, f := range faults {
		if _, ok := verdictSummaries[f.WorkReportHash]; !ok {
			return errors.WithMessagef(ErrInvalidFaults, "fault %s does not match any report hash in verdicts", f.WorkReportHash)
		}

		var statement string
		if f.Vote {
			statement = crypto.JamValidJudgementStatement
		} else {
			statement = crypto.JamInvalidJudgementStatement
		}
		msg := append([]byte(statement), f.WorkReportHash[:]...)
		if !ed25519.Verify(f.FaultKey, msg, f.Signature) {
			return errors.WithMessagef(ErrInvalidFaults, "fault %s has an invalid signature", f.WorkReportHash)
		}

		faultsByReportHash[f.WorkReportHash] = append(faultsByReportHash[f.WorkReportHash], f)
		offenders = append(offenders, ed25519.PublicKey(f.FaultKey))
	}

	for _, summary := range verdictSummaries {
		var validVote bool

		switch summary.ReportLabel {
		case GoodReportLabel:
			validVote = true

			// Faults should contain at least one valid entry.
			if len(faultsByReportHash[summary.WorkReportHash]) < 1 {
				return errors.WithMessagef(ErrInvalidFaults, "no valid faults for good report %s", summary.WorkReportHash)
			}
			ds.GoodReports = append(ds.GoodReports, summary.WorkReportHash)
		case BadReportLabel:
			validVote = false
			// Culprits should contain at least two valid entries.
			if len(calpritsByReportHash[summary.WorkReportHash]) < 2 {
				return errors.WithMessagef(ErrInvalidCulprits, "not enough valid culprits for bad report %s", summary.WorkReportHash)
			}
			ds.BadReports = append(ds.BadReports, summary.WorkReportHash)
		case WonkeyReportLabel:
			ds.WonkeyReports = append(ds.WonkeyReports, summary.WorkReportHash)
		default:
		}

		var effectiveValidatorsSet map[string]struct{}
		if summary.Epoch.Equal(epoch) {
			effectiveValidatorsSet = activeValidatorsSet
		} else {
			effectiveValidatorsSet = archivedValidatorsSet
		}

		for _, c := range calpritsByReportHash[summary.WorkReportHash] {
			if _, ok := effectiveValidatorsSet[string(c.CulpritKey)]; !ok {
				return errors.WithMessagef(ErrInvalidCulprits, "culprit %s is not an active or archived validator", string(c.CulpritKey))
			}
		}

		for _, f := range faultsByReportHash[summary.WorkReportHash] {
			if f.Vote == validVote {
				return errors.WithMessagef(ErrInvalidFaults, "fault %s has invalid vote: expected %t, got %t", f.WorkReportHash, validVote, f.Vote)
			}
			if _, ok := effectiveValidatorsSet[string(f.FaultKey)]; !ok {
				return errors.WithMessagef(ErrInvalidFaults, "fault %s is not an active or archived validator", string(f.FaultKey))
			}
		}
	}

	if ds.containsPunishedValidators(offenders) {
		return errors.New("seen validator already punished in the past")
	}
	ds.Offenders = append(ds.Offenders, offenders...)

	return nil
}
