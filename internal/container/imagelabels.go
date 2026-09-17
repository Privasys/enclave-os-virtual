// Copyright (c) Privasys. All rights reserved.

package container

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// ImageMountRoot is the only host directory an image may mount from via its
// own "ai.privasys.volume" label. It is where the disk-mounter stages model
// volumes, which is what the label exists to serve.
//
// Anything outside this root has to come from the deploy request, where the
// control plane can apply policy. See checkImageMountSource.
const ImageMountRoot = "/mnt"

// nvidiaNumberedDevice matches the per-GPU character devices, /dev/nvidia0,
// /dev/nvidia1 and so on.
var nvidiaNumberedDevice = regexp.MustCompile(`^/dev/nvidia[0-9]+$`)

// nvidiaFixedDevices are the NVIDIA control nodes a GPU container needs
// alongside the numbered devices.
// Deliberately no /dev/nvidia-caps entry: containerd expands a directory into
// every device beneath it, which would reopen the wildcard this allowlist
// exists to close. A MIG deployment that needs those nodes should name them in
// the deploy request.
var nvidiaFixedDevices = map[string]bool{
	"/dev/nvidiactl":        true,
	"/dev/nvidia-uvm":       true,
	"/dev/nvidia-uvm-tools": true,
	"/dev/nvidia-modeset":   true,
}

// isAllowedImageDevice reports whether an image may grant itself this host
// device through its "ai.privasys.devices" label.
//
// The label is read from the image's own config and each entry is handed to
// oci.WithDevices with "rwm" -- read, write and mknod on whatever host path
// the image names. That put the authority to grant host device access with the
// image rather than with the deploy request, which matters most where the
// image publisher is not the deployer.
//
// The label exists so that a plain deploy of a GPU image gets passthrough with
// no per-deploy input, so it stays limited to the GPU nodes that serve that
// purpose. Every other device must be named by the deploy request.
func isAllowedImageDevice(path string) bool {
	if path != filepath.Clean(path) || !strings.HasPrefix(path, "/dev/") {
		return false
	}
	return nvidiaFixedDevices[path] || nvidiaNumberedDevice.MatchString(path)
}

// checkImageMountSource reports whether an image may bind-mount this host path
// through its "ai.privasys.volume" label.
//
// Validation on this label used to be a length check on the split, with no
// allowlist on the source, so "/:/host:rw" mounted the whole host filesystem
// into the container. The source must now resolve inside ImageMountRoot.
//
// Follows the containment pattern of diskRefDir: reject traversal early, clean
// the path, then assert the cleaned result is still under the root.
func checkImageMountSource(source string) error {
	if source == "" {
		return fmt.Errorf("empty mount source")
	}
	if strings.Contains(source, "..") {
		return fmt.Errorf("mount source must not contain '..': %s", source)
	}
	clean := filepath.Clean(source)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("mount source must be absolute: %s", source)
	}
	root := filepath.Clean(ImageMountRoot)
	if clean == root {
		return nil
	}
	if !strings.HasPrefix(clean+string(filepath.Separator), root+string(filepath.Separator)) {
		return fmt.Errorf(
			"mount source %s is outside %s; a mount from anywhere else must be granted by the deploy request",
			source, ImageMountRoot)
	}
	return nil
}
