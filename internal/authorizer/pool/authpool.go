package authpool

import (
	"slices"

	authqueue "github.com/shunsukew/gojam/internal/authorizer/queue"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/pkg/common"
)

const (
	// The maximum number of items in the authorizations pool.
	MaxAuthorizerPoolSize = 8 // O
)

// α ∈ ⟦ ⟦H⟧:o ⟧c
// Core to authorizer hash array mapping
// α′ is dependent on φ′
type AuthorizerPools [common.NumOfCores]AuthorizerPool

type AuthorizerPool []common.Hash

// TODO: This function requires post state of Authorizers queue before processing.
func (pools *AuthorizerPools) Update(
	timeSlot jamtime.TimeSlot,
	authorizerHashes map[uint8]common.Hash, // core to authorizer hash mapping
	queues *authqueue.AuthorizerQueues,
) {
	for coreIndex := range pools {
		var coreAuthorizerHash *common.Hash
		if hash, ok := authorizerHashes[uint8(coreIndex)]; ok {
			coreAuthorizerHash = &hash
		}
		pools[coreIndex].Update(timeSlot, coreAuthorizerHash, queues[coreIndex])
	}
}

func (corePool *AuthorizerPool) Update(timeSlot jamtime.TimeSlot, authorizerHash *common.Hash, coreQueue *authqueue.AuthorizerQueue) {
	if authorizerHash != nil {
		corePool.RemoveAuthorizerHash(*authorizerHash)
	}

	*corePool = append(*corePool, coreQueue[timeSlot%authqueue.AuthorizerQueueSize])
	if len(*corePool) > MaxAuthorizerPoolSize {
		*corePool = (*corePool)[len(*corePool)-MaxAuthorizerPoolSize:]
	}
}

func (corePool *AuthorizerPool) RemoveAuthorizerHash(authorizerHash common.Hash) {
	for i, hash := range *corePool {
		if hash == authorizerHash {
			*corePool = slices.Delete(*corePool, i, i+1)
			return
		}
	}
}
