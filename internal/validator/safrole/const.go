//go:build !tiny

package safrole

const (
	NumOfTicketEntries    = 2  // N: The number of ticket entries per validator.
	MaxTicketsInExtrinsic = 16 // K: The number of tickets in an extrinsic.
)
