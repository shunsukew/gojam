//go:build !tiny

package common

const (
	NumOfCores                   = 341  // C: The number of cores.
	NumOfValidators              = 1023 // V = 1023: The total number of validators.
	NumOfSuperMajorityValidators = 682  // 2/3V + 1
	NumOfMinorityValidators      = 341  // 1/3V
)
