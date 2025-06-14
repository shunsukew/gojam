//go:build tiny

package jamtime

const (
	TimeSlotsPerEpoch        = 12
	TicketSubmissionDeadline = 10
	GuarantorRotationPeriod  = 4 // R

	MaxLookupAnchorAge TimeSlot = 14400 // L: The maximum age in timeslots of the lookup anchor.
)
