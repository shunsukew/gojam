//go:build !tiny

package jamtime

const (
	TimeSlotsPerEpoch        = 600 // E
	TicketSubmissionDeadline = 500 // Y
	GuarantorRotationPeriod  = 10  // R
)
