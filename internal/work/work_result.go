package work

import "github.com/shunsukew/gojam/pkg/common"

// (11.6) L ≡ (s ∈ NS , c ∈ H, l ∈ H, g ∈ NG , o ∈ Y ∪ J)
type WorkResult struct {
	ServiceIndex    uint32      // s ∈ NS
	ServiceCodeHash common.Hash // c ∈ H
	PayloadHash     common.Hash // l ∈ H
	Gas             uint64      // g ∈ NG
	ExecResult      *ExecResult // o ∈ Y ∪ J
}

type ExecResult struct {
	Output []byte    // Y
	Error  ExecError // J ∈ {∞, ☇, ⊚, BAD, BIG}
}

type ExecError int
