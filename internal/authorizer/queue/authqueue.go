package authqueue

import "github.com/shunsukew/gojam/pkg/common"

const (
	// The number of items in the authorizations queue.
	AuthorizerQueueSize = 80 // Q
)

//  φ ∈ ⟦ ⟦H⟧ Q⟧C
type AuthorizerQueues [common.NumOfCores]*AuthorizerQueue

type AuthorizerQueue [AuthorizerQueueSize]common.Hash
