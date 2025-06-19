package mmr

// TODO: implement own kecc
import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/shunsukew/gojam/pkg/common"
)

type MMR []*common.Hash

func (mmr MMR) SuperPeak() common.Hash {
	// Collect all non-nil peaks
	var peaks []*common.Hash
	for _, peak := range mmr {
		if peak != nil {
			peaks = append(peaks, peak)
		}
	}

	// No peaks: return empty hash
	if len(peaks) == 0 {
		return common.Hash{}
	}

	// Single peak: return as-is
	if len(peaks) == 1 {
		return *peaks[0]
	}

	// Multiple peaks: recursively combine
	lastPeak := peaks[len(peaks)-1]
	rest := MMR(peaks[:len(peaks)-1])
	restSuperPeak := rest.SuperPeak()

	// Concatenate: "peak" || restRoot || lastPeak
	data := append([]byte("peak"), restSuperPeak[:]...)
	data = append(data, lastPeak[:]...)

	return common.Hash(crypto.Keccak256Hash(data))
}

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

	hash := hasher((*mmr[level])[:], (*leaf)[:])

	mmr = setPeak(mmr, level, nil)
	return insertLeaf(mmr, &hash, level+1, hasher)
}

func setPeak(mmr MMR, level int, peak *common.Hash) MMR {
	newMMR := make(MMR, len(mmr))
	copy(newMMR, mmr)
	newMMR[level] = peak
	return newMMR
}
