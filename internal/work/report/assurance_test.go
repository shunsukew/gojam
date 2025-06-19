package workreport

import (
	"testing"

	"github.com/shunsukew/gojam/pkg/codec"
	"github.com/shunsukew/gojam/pkg/common"
)

func TestVerifyAssuranceSignature(t *testing.T) {
	tests := []struct {
		name                     string
		numOfCores               int
		anchorParentHash         string
		workReportAvailabilities string
		validatorPubkey          string
		signature                string
		expected                 bool
	}{
		{
			name:                     "valid signature",
			numOfCores:               common.NumOfCores,
			anchorParentHash:         "0xd61a38a0f73beda90e8c1dfba731f65003742539f4260694f44e22cabef24a8e",
			workReportAvailabilities: "0xfcfddfdd000000000000000000000000000000000000000000000000000000000000000000000000000000",
			validatorPubkey:          "0x4418fb8c85bb3985394a8c2756d3643457ce614546202a2f50b093d762499ace",
			signature:                "0x731f2df410df3fd924bffcf2a776c14a15c8487732271ae4ebf856b61375b6bed8a09739467ba77c89d65a3c78a6db46628e013cbf771dd70e5669169f84130c",
			expected:                 true,
		},
		{
			name:                     "invalid signature",
			numOfCores:               common.NumOfCores,
			anchorParentHash:         "0xd61a38a0f73beda90e8c1dfba731f65003742539f4260694f44e22cabef24a8e",
			workReportAvailabilities: "0xffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000",
			validatorPubkey:          "0xc933bdf43b68ade1cdf403fc14c8e8b0efe32c673c11580747941be01c792def",
			signature:                "0xe4a10b788274a58a3e1656d53cb371611e640830556568d505784b5b897622257df2b33731b06dd6bdca2c7fab31ed994350ca89d0d43b5bae6b24f71abebb05",
			expected:                 false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parentHash := common.HexToHash(test.anchorParentHash)
			workReportAvailabilities := common.FromHex(test.workReportAvailabilities)
			validatorPubkey := common.FromHex(test.validatorPubkey)
			signature := common.FromHex(test.signature)

			var availabilities [341]bool
			decoded := codec.DecodeBitSequence(workReportAvailabilities, common.NumOfCores)
			copy(availabilities[:], decoded)
			result := verifyAssuranceSignature(parentHash, availabilities, validatorPubkey, signature)
			if result != test.expected {
				t.Errorf("expected %v, got %v", test.expected, result)
			}
		})
	}
}
