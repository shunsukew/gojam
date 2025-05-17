package mmr

import "github.com/shunsukew/gojam/pkg/common"

type MMR []*common.Hash

// Append returns a new MMR with the given hash appended, without modifying the original.
func Append(r MMR, l common.Hash, hasher func(...[]byte) common.Hash) MMR {
	return P(r, &l, 0, hasher)
}

// P recursively merges the hash into the MMR without modifying original data
func P(r MMR, l *common.Hash, n int, hasher func(...[]byte) common.Hash) MMR {
	if n >= len(r) {
		return append(r, l)
	}

	if r[n] == nil {
		return R(r, n, l)
	}

	// Combine existing peak with new leaf
	concatinated := append((*r[n])[:], (*l)[:]...)
	hash := hasher(concatinated)

	// Clear current peak (immutably), recurse with combined
	r = R(r, n, nil)
	return P(r, &hash, n+1, hasher)
}

// R returns a new MMR with index `i` set to `v`, copying the input
func R(s MMR, i int, v *common.Hash) MMR {
	newS := make(MMR, len(s))
	copy(newS, s)
	newS[i] = v
	return newS
}
