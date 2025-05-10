//go:build tiny

package safrole

// Tiny Spec: https://docs.jamcha.in/basics/chain-spec/Tiny
const (
	NumOfTicketEntries    = 3
	MaxTicketEntryIndex   = 2 // entry index should be 0 or 1 or 2.
	MaxTicketsInExtrinsic = 3
)
