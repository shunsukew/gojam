package serviceaccounts_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/service"
	"github.com/shunsukew/gojam/pkg/common"
	testutils "github.com/shunsukew/gojam/test/utils"
	"github.com/stretchr/testify/require"
)

func TestServiceAccountsStateTransition(t *testing.T) {
	t.Run(testSpec, func(t *testing.T) {
		filePaths, err := testutils.GetJsonFilePaths(vectorFolderPath)
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
	Preimages []PreimageInput  `json:"preimages"`
	Slot      jamtime.TimeSlot `json:"slot"`
}

type PreimageInput struct {
	Requester uint32      `json:"requester"`
	Blob      common.Blob `json:"blob"`
}

type State struct {
	Accounts   []Account        `json:"accounts"`
	Statistics []StatisticsItem `json:"statistics"`
}

type Account struct {
	Id   service.ServiceId `json:"id"`
	Data Data              `json:"data"`
}

type Data struct {
	Preimages  []Preimage       `json:"preimages"`
	LookupMeta []LookupMetaItem `json:"lookup_meta"`
}

type Preimage struct {
	Hash common.Hash `json:"hash"`
	Blob common.Blob `json:"blob"`
}

type LookupMetaItem struct {
	Key struct {
		Hash   common.Hash `json:"hash"`
		Length uint32      `json:"length"`
	} `json:"key"`
	Value []uint32 `json:"value"`
}

type StatisticsItem struct {
	Id     service.ServiceId `json:"id"`
	Record struct {
		ProvidedCount     uint32 `json:"provided_count"`
		ProvidedSize      uint32 `json:"provided_size"`
		RefinementCount   uint32 `json:"refinement_count"`
		RefinementGasUsed uint32 `json:"refinement_gas_used"`
		Imports           uint32 `json:"imports"`
		Exports           uint32 `json:"exports"`
		ExtrinsicSize     uint32 `json:"extrinsic_size"`
		ExtrinsicCount    uint32 `json:"extrinsic_count"`
		AccumulateCount   uint32 `json:"accumulate_count"`
		AccumulateGasUsed uint32 `json:"accumulate_gas_used"`
		OnTransferCount   uint32 `json:"on_transfer_count"`
		OnTransferGasUsed uint32 `json:"on_transfer_gas_used"`
	} `json:"record"`
}

type Output struct {
	Ok  *struct{} `json:"ok"`
	Err string    `json:"err"`
}
