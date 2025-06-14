//go:build !tiny

package jamtime

const (
	TimeSlotsPerEpoch        = 600 // E
	TicketSubmissionDeadline = 500 // Y
	GuarantorRotationPeriod  = 10  // R

	MaxLookupAnchorAge TimeSlot = 14400 // L: The maximum age in timeslots of the lookup anchor.
)
