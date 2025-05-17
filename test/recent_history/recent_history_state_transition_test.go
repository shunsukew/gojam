package recent_history_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/shunsukew/gojam/internal/history"
	"github.com/shunsukew/gojam/pkg/common"
	test_utils "github.com/shunsukew/gojam/test/utils"
	"github.com/stretchr/testify/require"
)

const (
	testSpec         = "Full"
	vectorFolderPath = "../../@jamtestvectors-davxy/history/data"
)

func TestRecentHistoryStateTransition(t *testing.T) {
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

				recentHistory := toRecentHistory(testVector.PreState)
				expectedRecentHistory := toRecentHistory(testVector.PostState)

				workPackageHashToSegmentRoot := make(map[common.Hash]common.Hash)
				for _, workPackage := range testVector.Input.WorkPackages {
					workPackageHashToSegmentRoot[workPackage.Hash] = workPackage.ExportsRoot
				}

				err = recentHistory.Update(
					testVector.Input.HeaderHash,
					testVector.Input.ParentStateRoot,
					testVector.Input.AccumulateRoot,
					workPackageHashToSegmentRoot,
				)
				require.NoError(t, err, "failed to update recent history")

				require.Equal(t, len(*expectedRecentHistory), len(*recentHistory), "recent history length mismatch")
				for i := range *expectedRecentHistory {
					require.Equal(t, (*expectedRecentHistory)[i].HeaderHash, (*recentHistory)[i].HeaderHash, "header hash mismatch")
					require.Equal(t, (*expectedRecentHistory)[i].StateRoot, (*recentHistory)[i].StateRoot, "state root mismatch")
					// require.Equal(t, (*expectedRecentHistory)[i].AccumulationResultMMR, (*recentHistory)[i].AccumulationResultMMR, "accumulation result MMR mismatch")
					require.Equal(t, (*expectedRecentHistory)[i].WorkPackageHashes, (*recentHistory)[i].WorkPackageHashes, "work package hashes mismatch")
				}

				// TODO: Finally check the entire recent history state
				// require.Equal(t, expectedRecentHistory, recentHistory, "recent history mismatch")
			})
		}
	})
}

func toRecentHistory(state State) *history.RecentHistory {
	recentHistory := &history.RecentHistory{}
	for _, block := range state.Beta {
		recentBlock := &history.RecentBlock{
			HeaderHash:        block.HeaderHash,
			StateRoot:         block.StateRoot,
			WorkPackageHashes: make(map[common.Hash]common.Hash),
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
	HeaderHash      common.Hash   `json:"header_hash"`
	ParentStateRoot common.Hash   `json:"parent_state_root"`
	AccumulateRoot  common.Hash   `json:"accumulate_root"`
	WorkPackages    []WorkPackage `json:"work_packages"`
}

type WorkPackage struct {
	Hash        common.Hash `json:"hash"`
	ExportsRoot common.Hash `json:"exports_root"`
}

type State struct {
	Beta []RecentBlock `json:"beta"`
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

type Output struct {
}
