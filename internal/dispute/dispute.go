package dispute

import (
	"bytes"
	"crypto/ed25519"

	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/pkg/common"
)

// ψ ≡ (ψg, ψb, ψw, ψo)
type DisputeState struct {
	GoodReports   []common.Hash       // ψg: The set of good work reports hashes.
	BadReports    []common.Hash       // ψb: The set of bad work reports hashes.
	WonkeyReports []common.Hash       // ψw: The set of wonkey work reports hashes.
	Offenders     []ed25519.PublicKey // ψo: The set of public keys of validators who have been punished.
}

func (ds *DisputeState) containsPastReportHashes(verdicts []*Verdict) (bool, common.Hash) {
	pastReportedHashes := ds.getPastWorkReports()
	for _, verdict := range verdicts {
		if _, ok := pastReportedHashes[verdict.WorkReportHash]; ok {
			return true, verdict.WorkReportHash
		}
	}
	return false, common.Hash{}
}

func (ds *DisputeState) getPastWorkReports() map[common.Hash]struct{} {
	pastReportedHashes := make(map[common.Hash]struct{}, len(ds.GoodReports)+len(ds.BadReports)+len(ds.WonkeyReports))
	for _, report := range ds.GoodReports {
		pastReportedHashes[report] = struct{}{}
	}
	for _, report := range ds.BadReports {
		pastReportedHashes[report] = struct{}{}
	}
	for _, report := range ds.WonkeyReports {
		pastReportedHashes[report] = struct{}{}
	}
	return pastReportedHashes
}

func (ds *DisputeState) containsPunishedValidators(keys []ed25519.PublicKey) bool {
	punishedSet := make(map[string]struct{}, len(ds.Offenders))
	for _, offender := range ds.Offenders {
		punishedSet[common.Bytes2Hex(offender)] = struct{}{}
	}
	for _, key := range keys {
		if _, exists := punishedSet[common.Bytes2Hex(key)]; exists {
			return true
		}
	}
	return false
}

type Verdicts []*Verdict

type Verdict struct {
	WorkReportHash common.Hash
	Epoch          jamtime.Epoch
	Judgements     *Judgements // judgements from 2/3 + 1 supermajority valudators is requirement
}

func (v *Verdict) TallyVotes() (*VerdictSummary, error) {
	var positiveVotes int
	for _, judgement := range *v.Judgements {
		if judgement.Vote {
			positiveVotes++
		}
	}

	var label ReportLabel
	switch positiveVotes {
	case 0:
		label = BadReportLabel
	case common.NumOfMinorityValidators:
		label = WonkeyReportLabel
	case common.NumOfSuperMajorityValidators:
		label = GoodReportLabel
	default:
		return nil, errors.WithMessagef(
			ErrInvalidVerdicts,
			"verdict for report hash %s has invalid number of positive votes: %d. must be either 0, one-third, or two-thirds-plus-on",
			v.WorkReportHash, positiveVotes,
		)
	}

	return &VerdictSummary{
		WorkReportHash: v.WorkReportHash,
		Epoch:          v.Epoch,
		PositiveVotes:  positiveVotes,
		ReportLabel:    label,
	}, nil
}

func (verdicts Verdicts) isSortedNonDuplicates() bool {
	for i := 1; i < len(verdicts); i++ {
		if bytes.Compare(verdicts[i-1].WorkReportHash[:], verdicts[i].WorkReportHash[:]) != -1 {
			return false
		}
	}
	return true
}

type Judgements [common.NumOfSuperMajorityValidators]*Judgement

type Judgement struct {
	Vote           bool
	ValidatorIndex uint32
	Signature      []byte // 𝔼
}

func (j *Judgements) isSortedNonDuplicates() bool {
	for i := 1; i < len(*j); i++ {
		if (*j)[i-1].ValidatorIndex >= (*j)[i].ValidatorIndex {
			return false
		}
	}
	return true
}

type Culprits []*Culprit

// c ∈ ⟦ℍ, ℍ_E, 𝔼⟧
type Culprit struct {
	WorkReportHash common.Hash       // r
	CulpritKey     ed25519.PublicKey // k
	Signature      []byte            // 𝔼
}

func (culprits Culprits) isSortedNonDuplicates() bool {
	for i := 1; i < len(culprits); i++ {
		if bytes.Compare(culprits[i-1].CulpritKey[:], culprits[i].CulpritKey[:]) != -1 {
			return false
		}
	}
	return true
}

func (culprits Culprits) groupByReportHash() map[common.Hash][]*Culprit {
	grouped := make(map[common.Hash][]*Culprit, len(culprits))
	for _, culprit := range culprits {
		grouped[culprit.WorkReportHash] = append(grouped[culprit.WorkReportHash], culprit)
	}
	return grouped
}

type Faults []*Fault

type Fault struct {
	WorkReportHash common.Hash       // r
	Vote           bool              // v
	FaultKey       ed25519.PublicKey // k
	Signature      []byte            // 𝔼
}

func (faults Faults) isSortedNonDuplicates() bool {
	for i := 1; i < len(faults); i++ {
		if bytes.Compare(faults[i-1].FaultKey[:], faults[i].FaultKey[:]) != -1 {
			return false
		}
	}
	return true
}

func (faults Faults) groupByReportHash() map[common.Hash][]*Fault {
	grouped := make(map[common.Hash][]*Fault, len(faults))
	for _, fault := range faults {
		grouped[fault.WorkReportHash] = append(grouped[fault.WorkReportHash], fault)
	}
	return grouped
}
