package reports_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/service"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
	"github.com/shunsukew/gojam/pkg/crypto/bls"
	test_utils "github.com/shunsukew/gojam/test/utils"

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

				// TODO
			})
		}
	})
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
