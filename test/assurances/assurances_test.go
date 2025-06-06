package assurances_test

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/service"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/internal/work"
	"github.com/shunsukew/gojam/pkg/codec"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
	"github.com/shunsukew/gojam/pkg/crypto/bls"
	test_utils "github.com/shunsukew/gojam/test/utils"

	workreport "github.com/shunsukew/gojam/internal/work/report"
	"github.com/stretchr/testify/require"
)

func TestWorkReportAssurances(t *testing.T) {
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

				if !strings.Contains(filePath, "assurances_for_stale_report-1") {
					return
				}

				var testVector TestVector
				err = json.Unmarshal(file, &testVector)
				if err != nil {
					require.NoError(t, err, "failed to unmarshal test vector: %s", filePath)
				}

				assurances := make([]*workreport.Assurance, len(testVector.Input.Assurances))
				for i, a := range testVector.Input.Assurances {
					assurances[i] = &workreport.Assurance{
						AnchorParentHash: a.Anchor,
						WorkReportAvailabilities: func() [common.NumOfCores]bool {
							bits := codec.DecodeBitSequence(common.FromHex(a.BitField), common.NumOfCores)
							var arr [common.NumOfCores]bool
							copy(arr[:], bits)
							return arr
						}(),
						ValidatorIndex: a.ValidatorIndex,
						Signature:      common.FromHex(a.Signature),
					}
				}

				timeSlot := testVector.Input.Slot
				parentHash := testVector.Input.Parent
				activeValidators := &[common.NumOfValidators]*keys.ValidatorKey{}
				for i, v := range testVector.PreState.CurrentValidators {
					activeValidators[i] = &keys.ValidatorKey{
						BandersnatchPublicKey: v.Bandersnatch,
						Ed25519PublicKey:      ed25519.PublicKey(common.FromHex(v.Ed25519)),
						BLSKey:                v.Bls,
						Metadata:              [keys.ValidatorKeyMetadataSize]byte(common.FromHex(v.Metadata)),
					}
				}

				pendingWorkReportsState := toPendingWorkReports(testVector.PreState.AvailAssignments)
				expectedPendingWorkReportsState := toPendingWorkReports(testVector.PostState.AvailAssignments)
				expectedOutput := testVector.Output

				availableReports, err := pendingWorkReportsState.AssureAvailabilities(timeSlot, assurances, parentHash, activeValidators)
				if expectedOutput.Err != "" {
					require.Error(t, err, "error expected: %v", expectedOutput.Err)
					return
				}

				require.NoError(t, err, "failed to assure availabilities")
				require.Equal(t, expectedPendingWorkReportsState, pendingWorkReportsState)

				expectedAvailableReports := toAvailableWorkReports(expectedOutput.Ok.Reported)
				require.Len(t, availableReports, len(expectedAvailableReports), "number of available reports mismatch")
				require.Equal(t, expectedAvailableReports, availableReports, "available reports mismatch")
			})
		}
	})
}

func toPendingWorkReports(availAssignments []*AvailAssignment) *workreport.PendingWorkReports {
	pendingWorkReports := &workreport.PendingWorkReports{}
	for i, assignment := range availAssignments {
		if assignment == nil {
			continue
		}

		pendingWorkReport := &workreport.PendingWorkReport{
			ReportedAt: assignment.Timeout, // TODO: Test vector should rename field from `timeout` to `reported_at`. Otherwise, really confusing. Actual timeout of reports in test vectors are `timeout` val + PendingWorkReportTimeout 5 slots.
			WorkReport: &workreport.WorkReport{
				AvailabilitySpecification: &workreport.AvailabilitySpecification{
					WorkPackageHash:  assignment.Report.PackageSpec.Hash,
					WorkBundleLength: assignment.Report.PackageSpec.Length,
					ErasureRoot:      assignment.Report.PackageSpec.ErasureRoot,
					SegmentRoot:      assignment.Report.PackageSpec.ExportsRoot,
					SegmentCount:     assignment.Report.PackageSpec.ExportsCount,
				},
				RefinementContext: &work.RefinementContext{
					AnchorHeaderHash:              assignment.Report.Context.Anchor,
					AnchorStateRoot:               assignment.Report.Context.StateRoot,
					AnchorBeefyRoot:               assignment.Report.Context.BeefyRoot,
					LookupAnchorHeaderHash:        assignment.Report.Context.LookupAnchor,
					LookupAnchorTimeSlot:          assignment.Report.Context.LookupAnchorSlot,
					PreRequisiteWorkPackageHashes: assignment.Report.Context.PreRequisites,
				},
				CoreIndex:      assignment.Report.CoreIndex,
				AuthorizerHash: assignment.Report.AuthorizerHash,
				Output:         common.Hex2Bytes(assignment.Report.AuthOutput),
				SegmentRootLookup: func() map[common.Hash]common.Hash {
					lookup := make(map[common.Hash]common.Hash, len(assignment.Report.SegmentRootLookup))
					for _, item := range assignment.Report.SegmentRootLookup {
						lookup[item.WorkPackageHash] = item.SegmentTreeRoot
					}
					return lookup
				}(),
				WorkResults: func() []*workreport.WorkResult {
					results := make([]*workreport.WorkResult, len(assignment.Report.Results))
					for j, result := range assignment.Report.Results {
						results[j] = &workreport.WorkResult{
							ServiceId:       result.ServiceId,
							ServiceCodeHash: result.CodeHash,
							PayloadHash:     result.PayloadHash,
							Gas:             result.AccumulateGas,
							ExecResult: &workreport.ExecResult{
								Output: common.Hex2Bytes(result.Result.Ok),
								// TODO: Check exec error, in jam test vectors, no vector has been prepared yet.
							},
						}
					}
					return results
				}(),
			},
		}

		pendingWorkReports[i] = pendingWorkReport
	}

	return pendingWorkReports
}

func toAvailableWorkReports(workReports []Report) []*workreport.WorkReport {
	availableReports := make([]*workreport.WorkReport, len(workReports))
	for i, report := range workReports {
		availableReports[i] = &workreport.WorkReport{
			AvailabilitySpecification: &workreport.AvailabilitySpecification{
				WorkPackageHash:  report.PackageSpec.Hash,
				WorkBundleLength: report.PackageSpec.Length,
				ErasureRoot:      report.PackageSpec.ErasureRoot,
				SegmentRoot:      report.PackageSpec.ExportsRoot,
				SegmentCount:     report.PackageSpec.ExportsCount,
			},
			RefinementContext: &work.RefinementContext{
				AnchorHeaderHash:              report.Context.Anchor,
				AnchorStateRoot:               report.Context.StateRoot,
				AnchorBeefyRoot:               report.Context.BeefyRoot,
				LookupAnchorHeaderHash:        report.Context.LookupAnchor,
				LookupAnchorTimeSlot:          report.Context.LookupAnchorSlot,
				PreRequisiteWorkPackageHashes: report.Context.PreRequisites,
			},
			CoreIndex:      report.CoreIndex,
			AuthorizerHash: report.AuthorizerHash,
			Output:         common.Hex2Bytes(report.AuthOutput),
			SegmentRootLookup: func() map[common.Hash]common.Hash {
				lookup := make(map[common.Hash]common.Hash, len(report.SegmentRootLookup))
				for _, item := range report.SegmentRootLookup {
					lookup[item.WorkPackageHash] = item.SegmentTreeRoot
				}
				return lookup
			}(),
			WorkResults: func() []*workreport.WorkResult {
				results := make([]*workreport.WorkResult, len(report.Results))
				for j, result := range report.Results {
					results[j] = &workreport.WorkResult{
						ServiceId:       result.ServiceId,
						ServiceCodeHash: result.CodeHash,
						PayloadHash:     result.PayloadHash,
						Gas:             result.AccumulateGas,
						ExecResult: &workreport.ExecResult{
							Output: common.Hex2Bytes(result.Result.Ok),
							// TODO: Check exec error, in jam test vectors, no vector has been prepared yet.
						},
					}
				}
				return results
			}(),
		}
	}
	return availableReports
}

type TestVector struct {
	Input     Input  `json:"input"`
	PreState  State  `json:"pre_state"`
	PostState State  `json:"post_state"`
	Output    Output `json:"output"`
}

type Input struct {
	Assurances []Assurance      `json:"assurances"`
	Slot       jamtime.TimeSlot `json:"slot"`
	Parent     common.Hash      `json:"parent"`
}

type Assurance struct {
	Anchor         common.Hash `json:"anchor"`
	BitField       string      `json:"bitfield"`
	ValidatorIndex uint32      `json:"validator_index"`
	Signature      string      `json:"signature"`
}

type State struct {
	AvailAssignments  []*AvailAssignment `json:"avail_assignments"`
	CurrentValidators []ValidatorKey     `json:"curr_validators"`
}

type AvailAssignment struct {
	Report  Report           `json:"report"`
	Timeout jamtime.TimeSlot `json:"timeout"`
}

type Report struct {
	PackageSpec       PackageSpec             `json:"package_spec"`
	Context           Context                 `json:"context"`
	CoreIndex         uint32                  `json:"core_index"`
	AuthorizerHash    common.Hash             `json:"authorizer_hash"`
	AuthOutput        string                  `json:"auth_output"`
	SegmentRootLookup []SegmentRootLookupItem `json:"segment_root_lookup"`
	Results           []WorkResult            `json:"results"`
}

type PackageSpec struct {
	Hash         common.Hash `json:"hash"`
	Length       uint32      `json:"length"`
	ErasureRoot  common.Hash `json:"erasure_root"`
	ExportsRoot  common.Hash `json:"exports_root"`
	ExportsCount uint        `json:"exports_count"`
}

type Context struct {
	Anchor           common.Hash      `json:"anchor"`
	StateRoot        common.Hash      `json:"state_root"`
	BeefyRoot        common.Hash      `json:"beefy_root"`
	LookupAnchor     common.Hash      `json:"lookup_anchor"`
	LookupAnchorSlot jamtime.TimeSlot `json:"lookup_anchor_slot"`
	PreRequisites    []common.Hash    `json:"prerequisites"`
}

type SegmentRootLookupItem struct {
	WorkPackageHash common.Hash `json:"work_package_hash"`
	SegmentTreeRoot common.Hash `json:"segment_tree_root"`
}

type WorkResult struct {
	ServiceId     service.ServiceId `json:"service_id"`
	CodeHash      common.Hash       `json:"code_hash"`
	PayloadHash   common.Hash       `json:"payload_hash"`
	AccumulateGas service.Gas       `json:"accumulate_gas"`
	Result        Result            `json:"result"`
	// TODO: Check what those test data for.
	// RefineLoad    RefineLoad        `json:"refine_load"`
	// AuthGasUsed   uint64            `json:"auth_gas_used"`
}

type Result struct {
	Ok string `json:"ok"`
}

// type RefineLoad struct {
// GasUsed        uint64 `json:"gas_used"`
// Imports        uint32 `json:"imports"`
// ExtrinsicCount uint32 `json:"extrinsic_count"`
// ExtrinsicSize  uint32 `json:"extrinsic_size"`
// Exports        uint32 `json:"exports"`
// }

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
	Reported []Report `json:"reported"`
}
