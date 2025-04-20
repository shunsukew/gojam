package entropy

import (
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
	"golang.org/x/crypto/blake2b"
)

const (
	// η ∈ [H]4
	EntropyPoolSize = 4
)

// EntropyPool[0] is the current entropy accumulator at a "timeslot".
// EntropyPool[1] ~ EntropyPool[3] are historical entropies in previous "epochs".
type EntropyPool [EntropyPoolSize]common.Hash

func (ep *EntropyPool) RotateEntropies(vrfOutput bandersnatch.VrfOutput) {
	ep.rotateHistoricalEntropies()
	ep.updateEntropy(vrfOutput)
}

func (ep *EntropyPool) rotateHistoricalEntropies() {
	// keep ep[0] as it is, expected to be updated right after.
	for i := EntropyPoolSize - 1; i > 0; i-- {
		ep[i] = ep[i-1]
	}
}

// Should be invoked at each timeslot
// Gray Paper equation (6.22)
func (ep *EntropyPool) updateEntropy(vrfOutput bandersnatch.VrfOutput) {
	ep[0] = blake2b.Sum256(append(ep[0][:], vrfOutput[:]...))
}
