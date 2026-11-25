package container

import "github.com/containerd/containerd/v2/pkg/oci"

// droppedCapabilities are removed from every app container. CAP_NET_RAW would
// let an app craft frames to the bridge gateway addressed to another app; the
// FORWARD drop (network.forwardDrops) closes that path, and without raw
// sockets an app cannot even try. Costs ping inside apps.
var droppedCapabilities = []string{"CAP_NET_RAW"}

// appHardening are the spec options every app container gets on top of the
// image's own configuration.
func appHardening() []oci.SpecOpts {
	return []oci.SpecOpts{oci.WithDroppedCapabilities(droppedCapabilities)}
}
