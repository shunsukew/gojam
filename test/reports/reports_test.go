package reports_test

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	authpool "github.com/shunsukew/gojam/internal/authorizer/pool"
	"github.com/shunsukew/gojam/internal/entropy"
	"github.com/shunsukew/gojam/internal/history"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/service"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/internal/work"
	workreport "github.com/shunsukew/gojam/internal/work/report"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
	"github.com/shunsukew/gojam/pkg/crypto/bls"
	"github.com/shunsukew/gojam/pkg/mmr"
	test_utils "github.com/shunsukew/gojam/test/utils"

	"github.com/stretchr/testify/require"
)

func TestWorkReportGuarantee(t *testing.T) {
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

				pendingWorkReportsState := toPendingWorkReports(testVector.PreState.AvailAssignments)
				expectedPendingWorkReportsState := toPendingWorkReports(testVector.PostState.AvailAssignments)
				expectedOutput := testVector.Output

				_, err = pendingWorkReportsState.GuaranteeNewWorkReports(
					toGuarantees(testVector.Input.Guarantees),
					testVector.Input.Slot,
					toEntropyPool(testVector.PreState.Entropy),
					toValidatorKeys(testVector.PreState.CurrentValidators),
					toValidatorKeys(testVector.PreState.PrevValidators),
					toAuthorizerPools(testVector.PreState.AuthPools),
					toServices(testVector.PreState.Accounts),
					toRecentHistory(testVector.PreState.RecentBlocks),
				)
				if expectedOutput.Err != "" {
					require.Error(t, err, "error expected: %v", expectedOutput.Err)
					return
				}

				require.NoError(t, err, "failed to guarantee new work reports")
				require.Equal(t, expectedPendingWorkReportsState, pendingWorkReportsState, "pending work reports state should match expected state")
			})
		}
	})
}

func toGuarantees(input []Guarantee) workreport.Guarantees {
	guarantees := make(workreport.Guarantees, len(input))
	for i, g := range input {
		guarantees[i] = &workreport.Guarantee{
			Timeslot: g.Slot,
			Credentials: func() []*workreport.Credential {
				credentials := make([]*workreport.Credential, len(g.Signatures))
				for j, sig := range g.Signatures {
					credentials[j] = &workreport.Credential{
						ValidatorIndex: sig.ValidatorIndex,
						Signature:      common.Hex2Bytes(sig.Signature),
					}
				}
				return credentials
			}(),
			WorkReport: &workreport.WorkReport{
				AvailabilitySpecification: &workreport.AvailabilitySpecification{
					WorkPackageHash:  g.Report.PackageSpec.Hash,
					WorkBundleLength: g.Report.PackageSpec.Length,
					ErasureRoot:      g.Report.PackageSpec.ErasureRoot,
					SegmentRoot:      g.Report.PackageSpec.ExportsRoot,
					SegmentCount:     g.Report.PackageSpec.ExportsCount,
				},
				RefinementContext: &work.RefinementContext{
					AnchorHeaderHash:              g.Report.Context.Anchor,
					AnchorStateRoot:               g.Report.Context.StateRoot,
					AnchorBeefyRoot:               g.Report.Context.BeefyRoot,
					LookupAnchorHeaderHash:        g.Report.Context.LookupAnchor,
					LookupAnchorTimeSlot:          g.Report.Context.LookupAnchorSlot,
					PreRequisiteWorkPackageHashes: g.Report.Context.PreRequisites,
				},
				CoreIndex:      g.Report.CoreIndex,
				AuthorizerHash: g.Report.AuthorizerHash,
				Output:         common.Hex2Bytes(g.Report.AuthOutput),
				SegmentRootLookup: func() map[common.Hash]common.Hash {
					lookup := make(map[common.Hash]common.Hash, len(g.Report.SegmentRootLookup))
					for _, item := range g.Report.SegmentRootLookup {
						lookup[item.WorkPackageHash] = item.SegmentTreeRoot
					}
					return lookup
				}(),
				WorkResults: func() []*workreport.WorkResult {
					results := make([]*workreport.WorkResult, len(g.Report.Results))
					for j, result := range g.Report.Results {
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
	}
	return guarantees
}

func toValidatorKeys(input []ValidatorKey) *[common.NumOfValidators]*keys.ValidatorKey {
	validatorKeys := &[common.NumOfValidators]*keys.ValidatorKey{}
	for i, v := range input {
		validatorKeys[i] = &keys.ValidatorKey{
			BandersnatchPublicKey: v.Bandersnatch,
			Ed25519PublicKey:      ed25519.PublicKey(common.FromHex(v.Ed25519)),
			BLSKey:                v.Bls,
			Metadata:              [keys.ValidatorKeyMetadataSize]byte(common.FromHex(v.Metadata)),
		}
	}
	return validatorKeys
}

func toEntropyPool(input []common.Hash) *entropy.EntropyPool {
	entropyPool := entropy.EntropyPool{}
	for i := range len(entropyPool) {
		entropyPool[i] = input[i]
	}
	return &entropyPool
}

func toAuthorizerPools(input []AuthPool) *authpool.AuthorizerPools {
	authorizerPools := authpool.AuthorizerPools{}
	for i, pool := range input {
		authorizerPools[i] = make([]common.Hash, len(pool))
		copy(authorizerPools[i], pool)
	}
	return &authorizerPools
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

func toServices(input []Account) *service.Services {
	services := &service.Services{}
	for _, account := range input {
		services.Save(account.Id, &service.ServiceAccount{
			CodeHash: account.Data.Service.CodeHash,
			Balance:  account.Data.Service.Balance,
		})
	}
	return services
}

func toRecentHistory(input []RecentBlock) *history.RecentHistory {
	recentHistory := &history.RecentHistory{}
	for _, block := range input {
		recentBlock := &history.RecentBlock{
			HeaderHash:            block.HeaderHash,
			StateRoot:             block.StateRoot,
			AccumulationResultMMR: *(*mmr.MMR)(&block.MMR.Peaks),
			WorkPackageHashes:     make(map[common.Hash]common.Hash),
		}
		for _, reported := range block.Reported {
			recentBlock.WorkPackageHashes[reported.Hash] = reported.ExportsRoot
		}
		*recentHistory = append(*recentHistory, recentBlock)
	}
	return recentHistory
}

type TestVector struct {
	Input     Input  `json:"input"`
	PreState  State  `json:"pre_state"`
	PostState State  `json:"post_state"`
	Output    Output `json:"output"`
}

type Input struct {
	Guarantees    []Guarantee      `json:"guarantees"`
	Slot          jamtime.TimeSlot `json:"slot"`
	KnownPackages []common.Hash    `json:"known_packages"`
}

type Guarantee struct {
	Report     Report           `json:"report"`
	Slot       jamtime.TimeSlot `json:"slot"`
	Signatures []Signature      `json:"signatures"`
}

type Signature struct {
	ValidatorIndex uint32 `json:"validator_index"`
	Signature      string `json:"signature"`
}

type State struct {
	AvailAssignments  []*AvailAssignment  `json:"avail_assignments"`
	CurrentValidators []ValidatorKey      `json:"curr_validators"`
	PrevValidators    []ValidatorKey      `json:"prev_validators"`
	Entropy           []common.Hash       `json:"entropy"`
	Offenders         []string            `json:"offenders"`
	RecentBlocks      []RecentBlock       `json:"recent_blocks"`
	AuthPools         []AuthPool          `json:"auth_pools"`
	Accounts          []Account           `json:"accounts"`
	CoreStatistics    []CoreStatistics    `json:"core_statistics"`
	ServiceStatistics []ServiceStatistics `json:"service_statistics"`
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
	AuthGasUsed       uint64                  `json:"auth_gas_used"`
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
	RefineLoad    RefineLoad        `json:"refine_load"`
	AuthGasUsed   uint64            `json:"auth_gas_used"`
}

type Result struct {
	Ok string `json:"ok"`
}

type RefineLoad struct {
	GasUsed        uint64 `json:"gas_used"`
	Imports        uint32 `json:"imports"`
	ExtrinsicCount uint32 `json:"extrinsic_count"`
	ExtrinsicSize  uint32 `json:"extrinsic_size"`
	Exports        uint32 `json:"exports"`
}

type ValidatorKey struct {
	Bandersnatch bandersnatch.PublicKey `json:"bandersnatch"`
	Ed25519      string                 `json:"ed25519"`
	Bls          bls.BLSKey             `json:"bls"`
	Metadata     string                 `json:"metadata"`
}

type RecentBlock struct {
	HeaderHash common.Hash `json:"header_hash"`
	MMR        MMR         `json:"mmr"`
	StateRoot  common.Hash `json:"state_root"`
	Reported   []Reported  `json:"reported"`
}

type MMR struct {
	Peaks []*common.Hash `json:"peaks"`
}

type Reported struct {
	Hash        common.Hash `json:"hash"`
	ExportsRoot common.Hash `json:"exports_root"`
}

type AuthPool []common.Hash

type Account struct {
	Id   service.ServiceId `json:"id"`
	Data struct {
		Service Service `json:"service"`
	} `json:"data"`
}

type Service struct {
	CodeHash   common.Hash     `json:"code_hash"`
	Balance    service.Balance `json:"balance"`
	MinItemGas service.Gas     `json:"min_item_gas"`
	MinMemoGas service.Gas     `json:"min_memo_gas"`
	Bytes      uint32          `json:"bytes"`
	Items      uint32          `json:"items"`
}

type CoreStatistics struct {
	DALoad         uint32 `json:"da_load"`
	Popularity     uint32 `json:"popularity"`
	Imports        uint32 `json:"imports"`
	Exports        uint32 `json:"exports"`
	ExtrinsicSize  uint32 `json:"extrinsic_size"`
	ExtrinsicCount uint32 `json:"extrinsic_count"`
	BundleSize     uint32 `json:"bundle_size"`
	GasUsed        uint64 `json:"gas_used"`
}

type ServiceStatistics struct {
	Id     service.ServiceId `json:"id"`
	Record struct {
		ProvidedCount     uint32 `json:"provided_count"`
		ProvidedSize      uint32 `json:"provided_size"`
		RefinementCount   uint32 `json:"refinement_count"`
		RefinementGasUsed uint64 `json:"refinement_gas_used"`
		Imports           uint32 `json:"imports"`
		Exports           uint32 `json:"exports"`
		ExtrinsicSize     uint32 `json:"extrinsic_size"`
		ExtrinsicCount    uint32 `json:"extrinsic_count"`
		AccumulateCount   uint32 `json:"accumulate_count"`
		AccumulateGasUsed uint64 `json:"accumulate_gas_used"`
		OnTransferCount   uint32 `json:"on_transfer_count"`
		OnTransferGasUsed uint64 `json:"on_transfer_gas_used"`
	} `json:"record"`
}

type Output struct {
	Ok  Ok     `json:"ok"`
	Err string `json:"err"`
}

type Ok struct {
	Reported []struct {
		WorkPackageHash common.Hash `json:"work_package_hash"`
		SegmentTreeRoot common.Hash `json:"segment_tree_root"`
	} `json:"reported"`
	Reporters []string `json:"reporters"`
}
