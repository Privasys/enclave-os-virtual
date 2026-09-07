package launcher

// ResourceDecl is a user-owned resource an app declares in its measured
// manifest (P1 of plans/drive-as-remote-disk.md), forwarded by the control
// plane in the load request. The runtime owns the consent flow that turns a
// declaration into a grant (P2); until that lands the declaration is
// recorded on the container spec and nothing is served for it.
type ResourceDecl struct {
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Permissions []string `json:"permissions"`
	Mount       string   `json:"mount,omitempty"`
}
