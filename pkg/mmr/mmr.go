package mmr

import "github.com/shunsukew/gojam/pkg/common"

type MMR []*common.Hash

// Append returns a new MMR with the given hash appended, without modifying the original.
func Append(mmr MMR, leaf common.Hash, hasher func(...[]byte) common.Hash) MMR {
	return insertLeaf(mmr, &leaf, 0, hasher)
}

func insertLeaf(mmr MMR, leaf *common.Hash, index int, hasher func(...[]byte) common.Hash) MMR {
	if index >= len(mmr) {
		return append(mmr, leaf)
	}

	if mmr[index] == nil {
		return setPeak(mmr, index, leaf)
	}

	hash := hasher(append((*mmr[index])[:], (*leaf)[:]...))

	mmr = setPeak(mmr, index, nil)
	return insertLeaf(mmr, &hash, index+1, hasher)
}

func setPeak(mmr MMR, index int, peak *common.Hash) MMR {
	newMMR := make(MMR, len(mmr))
	copy(newMMR, mmr)
	newMMR[index] = peak
	return newMMR
}
