//go:build !tiny

package safrole

const (
	NumOfTicketEntries    = 2  // N: The number of ticket entries per validator.
	MaxTicketEntryIndex   = 1  // entry index should be 0 or 1.
	MaxTicketsInExtrinsic = 16 // K: The number of tickets in an extrinsic.
)
