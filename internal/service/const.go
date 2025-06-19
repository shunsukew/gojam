package service

const (
	WorkReportAccumulationGasLimit = 10000000   // G_A: The gas allocated to invoke a work-report’s Accumulation logic.
	WorkPackageAuthorizeGasLimit   = 50000000   // G_I: The gas allocated to invoke a work-package’s Is-Authorized logic.
	WorkPackageRefineGasLimit      = 5000000000 // G_R: The gas allocated to invoke a work-package’s Refine logic.
)
