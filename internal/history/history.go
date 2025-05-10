package history

const (
	NumOfRetainedBlocks = 8 // H: the number of blocks to retain in history
)

type RecentHistory []*RecentBlock

type RecentBlock struct {
}
