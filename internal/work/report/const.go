package workreport

const (
	MaxDependencyItemsInReport = 8 // J = 8: The maximum sum of dependency items in a work-report.
	MaxCredentialsInGuarantee  = 3
	MaxCodeSize                = 4000000        // WC = 4,000,000: The maximum size of service code in octets.
	MaxWorkReportOutputsSize   = 48 * (1 << 10) // WR = 48*2^10: The maximum total size of all output blobs (sum of work report output + all work results' outputs) in a work-report, in octets.

	PendingWorkReportTimeout = 5
)
