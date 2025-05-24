package disputes_test

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/shunsukew/gojam/internal/dispute"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
	"github.com/shunsukew/gojam/pkg/crypto/bls"
	test_utils "github.com/shunsukew/gojam/test/utils"

	"github.com/stretchr/testify/require"
)

func TestDisputeStateTransition(t *testing.T) {
	t.Run(testSpec, func(t *testing.T) {
		filePaths, err := test_utils.GetJsonFilePaths(vectorFolderPath)
		if err != nil {
			require.NoError(t, err, "failed to get JSON file paths")
		}

		for _, filePath := range filePaths {
			testCase := fmt.Sprintf("Test %s", filepath.Base(filePath))
			t.Run(testCase, func(t *testing.T) {
				file, err := os.ReadFile(filePath)
				if err != nil {
					require.NoErrorf(t, err, "failed to read test vector file: %s", filePath)
				}

				var testVector TestVector
				err = json.Unmarshal(file, &testVector)
				if err != nil {
					require.NoError(t, err, "failed to unmarshal test vector: %s", filePath)
				}

				verticts := make([]*dispute.Verdict, len(testVector.Input.Verdicts))
				for i, v := range testVector.Input.Verdicts {
					judgements := &dispute.Judgements{}
					for j, vote := range v.Votes {
						(*judgements)[j] = &dispute.Judgement{
							Vote:           vote.Vote,
							ValidatorIndex: vote.Index,
							Signature:      common.FromHex(vote.Signature),
						}
					}
					verticts[i] = &dispute.Verdict{
						WorkReportHash: v.Target,
						Epoch:          jamtime.Epoch(v.Age),
						Judgements:     judgements,
					}
				}

				culprits := make([]*dispute.Culprit, len(testVector.Input.Culprits))
				for i, c := range testVector.Input.Culprits {
					culprits[i] = &dispute.Culprit{
						WorkReportHash: c.Target,
						CulpritKey:     ed25519.PublicKey(common.FromHex(c.Key)),
						Signature:      common.FromHex(c.Signature),
					}
				}

				faults := make([]*dispute.Fault, len(testVector.Input.Faults))
				for i, f := range testVector.Input.Faults {
					faults[i] = &dispute.Fault{
						WorkReportHash: f.Target,
						Vote:           f.Vote,
						FaultKey:       ed25519.PublicKey(common.FromHex(f.Key)),
						Signature:      common.FromHex(f.Signature),
					}
				}

				timeSlot := jamtime.TimeSlot(testVector.PreState.Tau)
				activeValidators := make([]*keys.ValidatorKey, len(testVector.PreState.Kappa))
				for i, v := range testVector.PreState.Kappa {
					activeValidators[i] = &keys.ValidatorKey{
						BandersnatchPublicKey: v.Bandersnatch,
						Ed25519PublicKey:      ed25519.PublicKey(common.FromHex(v.Ed25519)),
						BLSKey:                v.Bls,
						Metadata:              [keys.ValidatorKeyMetadataSize]byte(common.FromHex(v.Metadata)),
					}
				}
				archivedValidators := make([]*keys.ValidatorKey, len(testVector.PreState.Lambda))
				for i, v := range testVector.PreState.Lambda {
					archivedValidators[i] = &keys.ValidatorKey{
						BandersnatchPublicKey: v.Bandersnatch,
						Ed25519PublicKey:      ed25519.PublicKey(common.FromHex(v.Ed25519)),
						BLSKey:                v.Bls,
						Metadata:              [keys.ValidatorKeyMetadataSize]byte(common.FromHex(v.Metadata)),
					}
				}

				disputeState := toDisputeState(testVector.PreState)
				expectedDisputeState := toDisputeState(testVector.PostState)
				expectedOutput := testVector.Output

				err = disputeState.Update(
					dispute.Verdicts(verticts),
					dispute.Culprits(culprits),
					dispute.Faults(faults),
					activeValidators,
					archivedValidators,
					timeSlot,
				)
				if expectedOutput.Err != "" {
					require.Error(t, err, "error expected: %v", expectedOutput.Err)
				} else {
					require.NoError(t, err, "error unexpected: %s", err)
				}

				require.Equal(t, expectedDisputeState.GoodReports, disputeState.GoodReports, "Good reports mismatch")
				require.Equal(t, expectedDisputeState.BadReports, disputeState.BadReports, "Bad reports mismatch")
				require.Equal(t, expectedDisputeState.WonkeyReports, disputeState.WonkeyReports, "Wonkey reports mismatch")
				require.Equal(t, len(expectedDisputeState.Offenders), len(disputeState.Offenders), "Offenders length mismatch")
			})
		}
	})
}

func toDisputeState(state State) *dispute.DisputeState {
	disputeState := &dispute.DisputeState{
		GoodReports:   state.Psi.Good,
		BadReports:    state.Psi.Bad,
		WonkeyReports: state.Psi.Wonkey,
		Offenders:     make([]ed25519.PublicKey, len(state.Psi.Offenders)),
	}
	for i, offender := range state.Psi.Offenders {
		offenderKey := ed25519.PublicKey(common.FromHex(offender))
		disputeState.Offenders[i] = offenderKey
	}
	return disputeState
}

type TestVector struct {
	Input     Input  `json:"input"`
	PreState  State  `json:"pre_state"`
	PostState State  `json:"post_state"`
	Output    Output `json:"output"`
}

type Input struct {
	Verdicts []Verdict
	Culprits []Culprit
	Faults   []Fault
}

type Verdict struct {
	Target common.Hash      `json:"target"`
	Age    jamtime.TimeSlot `json:"age"`
	Votes  []Vote           `json:"votes"`
}

type Vote struct {
	Vote      bool   `json:"vote"`
	Index     uint8  `json:"index"`
	Signature string `json:"signature"`
}

type Culprit struct {
	Target    common.Hash `json:"target"`
	Key       string      `json:"key"`
	Signature string      `json:"signature"`
}

type Fault struct {
	Target    common.Hash `json:"target"`
	Vote      bool        `json:"vote"`
	Key       string      `json:"key"`
	Signature string      `json:"signature"`
}

type State struct {
	Psi    Psi               `json:"psi"`
	Rho    []*CoreAssignment `json:"rho"`
	Tau    jamtime.TimeSlot  `json:"tau"`
	Kappa  []ValidatorKey    `json:"kappa"`
	Lambda []ValidatorKey    `json:"lambda"`
}

type Psi struct {
	Good      []common.Hash `json:"good"`
	Bad       []common.Hash `json:"bad"`
	Wonkey    []common.Hash `json:"wonkey"`
	Offenders []string      `json:"offenders"`
}

type CoreAssignment struct{}

type ValidatorKey struct {
	Bandersnatch bandersnatch.PublicKey `json:"bandersnatch"`
	Ed25519      string                 `json:"ed25519"`
	Bls          bls.BLSKey             `json:"bls"`
	Metadata     string                 `json:"metadata"`
}

type Output struct {
	Ok  Ok     `json:"ok"`
	Err string `json:"err"`
}

type Ok struct {
	OffendersMark []string `json:"offenders_mark"`
}
