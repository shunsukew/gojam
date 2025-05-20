package authorizations_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	authpool "github.com/shunsukew/gojam/internal/authorizer/pool"
	authqueue "github.com/shunsukew/gojam/internal/authorizer/queue"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/pkg/common"
	test_utils "github.com/shunsukew/gojam/test/utils"
	"github.com/stretchr/testify/require"
)

func TestAuthorizationsStateTransition(t *testing.T) {
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

				timeSlot := testVector.Input.Slot
				authorizerHashes := make(map[uint8]common.Hash)
				for _, auth := range testVector.Input.Auths {
					authorizerHashes[auth.Core] = auth.AuthHash
				}

				authorizerPools := toAuthorizersPools(testVector.PreState.AuthPools)
				authorizerQueues := toAuthorizersQueues(testVector.PreState.AuthQueues)

				expectedAuthorizerPools := toAuthorizersPools(testVector.PostState.AuthPools)
				expectedAuthorizerQueues := toAuthorizersQueues(testVector.PostState.AuthQueues)

				authorizerPools.Update(timeSlot, authorizerHashes, &authorizerQueues)

				require.Equal(t, expectedAuthorizerPools, authorizerPools, "expected authorizations pools to match")
				require.Equal(t, expectedAuthorizerQueues, authorizerQueues, "expected authorizations queues to match")
			})
		}
	})
}

func toAuthorizersPools(pools []AuthPool) authpool.AuthorizerPools {
	authPools := authpool.AuthorizerPools{}
	for coreIndex, pool := range pools {
		coreAuthPool := make(authpool.AuthorizerPool, len(pool))
		copy(coreAuthPool, pool)
		authPools[coreIndex] = coreAuthPool
	}
	return authPools
}

func toAuthorizersQueues(queues []AuthQueue) authqueue.AuthorizerQueues {
	authQueues := authqueue.AuthorizerQueues{}
	for coreIndex, queue := range queues {
		coreAuthQueue := authqueue.AuthorizerQueue{}
		copy(coreAuthQueue[:], queue)
		authQueues[coreIndex] = &coreAuthQueue
	}
	return authQueues
}

type TestVector struct {
	Input     Input  `json:"input"`
	PreState  State  `json:"pre_state"`
	PostState State  `json:"post_state"`
	Output    Output `json:"output"`
}

type Input struct {
	Slot  jamtime.TimeSlot `json:"slot"`
	Auths []Auth           `json:"auths"`
}

type Auth struct {
	Core     uint8       `json:"core"`
	AuthHash common.Hash `json:"auth_hash"`
}

type State struct {
	AuthPools  []AuthPool  `json:"auth_pools"`
	AuthQueues []AuthQueue `json:"auth_queues"`
}

type AuthPool []common.Hash

type AuthQueue []common.Hash

type Output struct{}
