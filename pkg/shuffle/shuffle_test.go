package shuffle_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/shuffle"
	test_utils "github.com/shunsukew/gojam/test/utils"
	"github.com/stretchr/testify/require"
)

const (
	vectorFolderPath = "../../@jamtestvectors-davxy/shuffle"
)

func TestFisherYatesShuffle(t *testing.T) {
	t.Run("Shuffle", func(t *testing.T) {
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

				var testVectors []TestVector
				err = json.Unmarshal(file, &testVectors)
				if err != nil {
					require.NoError(t, err, "failed to unmarshal test vector: %s", filePath)
				}

				for _, testVector := range testVectors {
					t.Run(fmt.Sprintf("Input %d", testVector.Input), func(t *testing.T) {
						slice := make([]uint32, testVector.Input)
						for i := range testVector.Input {
							slice[i] = uint32(i)
						}
						shuffle.Shuffle(slice, testVector.Entropy)
						require.Equal(t, testVector.Output, slice, "shuffled output does not match expected output")
					})
				}
			})
		}
	})
}

type TestVector struct {
	Input   int         `json:"input"`
	Entropy common.Hash `json:"entropy"`
	Output  []uint32    `json:"output"`
}
