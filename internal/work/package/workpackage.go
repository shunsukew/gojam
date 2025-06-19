package workpackage

import (
	"github.com/shunsukew/gojam/internal/work"
	workitem "github.com/shunsukew/gojam/internal/work/item"
	"github.com/shunsukew/gojam/pkg/common"
)

// (14.2) P≡⎧ j ∈ Y, h ∈ Ns , u ∈ H, p ∈ Y, x ∈ X, w ∈ ⟦I⟧1:I ⎫
type Package struct {
	AuthToken         []byte                  // j ∈ Y
	ServiceIndex      uint32                  // h ∈ Ns
	AuthCodeHash      common.Hash             // u ∈ H
	AuthParam         []byte                  // p ∈ Y
	RefinementContext *work.RefinementContext // x ∈ X
	WorkItems         []*workitem.Item        // w ∈ ⟦I⟧1:I
}
