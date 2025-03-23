package block

type Extrinsic struct {
	TicketsExtrinsic     // ET: Tickets, used for the mechanism which manages the selection of validators for the permissioning of block authoring.
	PreimagesExtrinsic   // EP: Static data which is presently being requested to be available for workloads to be able to fetch on demand.
	GuaranteesExtrinsic  // EG: Reports of newly completed workloads whose accuracy is guaranteed by specific validators.
	AssuarancesExtrinsic // EA: Assurances by each validator concerning which of the input data of workloads they have correctly received and are storing locally.
	DisputesExtrinsic    // ED: Information relating to disputes between validators over the validity of reports.
}

type TicketsExtrinsic struct{}

type PreimagesExtrinsic struct{}

type GuaranteesExtrinsic struct{}

type AssuarancesExtrinsic struct{}

type DisputesExtrinsic struct{}
