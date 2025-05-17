package mmr

import "github.com/shunsukew/gojam/pkg/common"

type MMR []*common.Hash

// Append returns a new MMR with the given hash appended, without modifying the original.
func Append(mmr MMR, leaf common.Hash, hasher func(...[]byte) common.Hash) MMR {
	return insertLeaf(mmr, &leaf, 0, hasher)
}

func insertLeaf(mmr MMR, leaf *common.Hash, level int, hasher func(...[]byte) common.Hash) MMR {
	if level >= len(mmr) {
		return append(mmr, leaf)
	}

	if mmr[level] == nil {
		return setPeak(mmr, level, leaf)
	}

	hash := hasher(append((*mmr[level])[:], (*leaf)[:]...))

	mmr = setPeak(mmr, level, nil)
	return insertLeaf(mmr, &hash, level+1, hasher)
}

func setPeak(mmr MMR, level int, peak *common.Hash) MMR {
	newMMR := make(MMR, len(mmr))
	copy(newMMR, mmr)
	newMMR[level] = peak
	return newMMR
}
