package work

import "github.com/shunsukew/gojam/pkg/common"

// (14.2) P≡⎧ j ∈ Y, h ∈ Ns , u ∈ H, p ∈ Y, x ∈ X, w ∈ ⟦I⟧1:I ⎫
type WorkPackage struct {
	AuthToken    []byte      // j ∈ Y
	ServiceIndex uint32      // h ∈ Ns
	AuthCodeHash common.Hash // u ∈ H
	AuthParam    []byte      // p ∈ Y
	// Context // x ∈ X
	WorkItems []*WorkItem // w ∈ ⟦I⟧1:I
}
