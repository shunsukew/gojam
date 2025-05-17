package mmr

import (
	"testing"

	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto"
	"github.com/stretchr/testify/require"
)

func TestAppend(t *testing.T) {
	hasher := crypto.Keccak256Hash

	hash_1 := common.Hash{1}
	hash_2 := common.Hash{2}
	hash_3 := common.Hash{3}

	tests := []struct {
		name     string
		mmr      MMR
		leaf     common.Hash
		expected MMR
	}{
		{
			name:     "Empty MMR",
			mmr:      MMR{},
			leaf:     hash_1,
			expected: MMR{&hash_1},
		},
		{
			name: "Single Peak",
			mmr:  MMR{&hash_1},
			leaf: hash_2,
			expected: func() MMR {
				hash := hasher(hash_1[:], hash_2[:])
				return MMR{nil, &hash}
			}(),
		},
		{
			name: "Tow Peak with nil head",
			mmr:  MMR{nil, &hash_1},
			leaf: hash_2,
			expected: func() MMR {
				return MMR{&hash_2, &hash_1}
			}(),
		},
		{
			name: "Two Peaks",
			mmr:  MMR{&hash_2, &hash_1},
			leaf: hash_3,
			expected: func() MMR {
				hash_2_3 := hasher(hash_2[:], hash_3[:])
				hash_1_2_3 := hasher(hash_1[:], hash_2_3[:])
				return MMR{nil, nil, &hash_1_2_3}
			}(),
		},
		{
			name: "Three Peaks",
			mmr:  MMR{&hash_2, nil, &hash_1},
			leaf: hash_3,
			expected: func() MMR {
				hash_2_3 := hasher(hash_2[:], hash_3[:])
				return MMR{nil, &hash_2_3, &hash_1}
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Append(test.mmr, test.leaf, hasher)
			if len(result) != len(test.expected) {
				require.Equal(t, len(test.expected), len(result), "MMR length mismatch")
			}
			for i := range result {
				require.Equal(t, test.expected[i], result[i], "MMR hash mismatch")
			}
		})
	}
}
