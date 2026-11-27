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

// mergeDevices returns the host devices a container gets: the deploy
// request's, then the image label's (comma-separated host paths), each path
// once. The control plane already copies the label's devices into the
// request, so without the de-duplication each one was granted twice.
//
// The label is read from the image's own config, so honouring it
// unconditionally put the authority to grant host device access with the
// image rather than with the deploy request: an image declaring /dev/sda,
// /dev/mem or /dev/kvm received it, with rwm (read, write and mknod). That
// matters most where the image publisher is not the deployer, as with a store
// app. So an image may ask only for the GPU nodes the label exists to serve;
// any other device must come from the request, which the control plane
// stamps.
func mergeDevices(name string, requested []string, label string) ([]string, error) {
	var devices []string
	seen := map[string]bool{}
	add := func(d string) {
		if !seen[d] {
			seen[d] = true
			devices = append(devices, d)
		}
	}
	for _, d := range requested {
		add(d)
	}
	for _, d := range strings.Split(label, ",") {
		if d = strings.TrimSpace(d); d == "" {
			continue
		}
		if !isAllowedImageDevice(d) {
			return nil, fmt.Errorf(
				"container: %s image label ai.privasys.devices requests %q, which is not a GPU device node; "+
					"host devices other than the NVIDIA set must be granted by the deploy request",
				name, d)
		}
		add(d)
	}
	return devices, nil
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
//
// And within the root, an image may mount only a disk its DEPLOYMENT was
// assigned (assigned: disk names, "model-<x>" mounted by disk-mounter at
// ImageMountRoot/<x>): never the root itself (every disk on the VM), never a
// sibling deployment's disk. With nothing assigned, which is every
// deployment until the load request carries the assignment, every
// image-declared mount is refused.
func checkImageMountSource(source string, assigned []string) error {
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
	if !strings.HasPrefix(clean+string(filepath.Separator), root+string(filepath.Separator)) {
		return fmt.Errorf(
			"mount source %s is outside %s; a mount from anywhere else must be granted by the deploy request",
			source, ImageMountRoot)
	}
	for _, disk := range assigned {
		name := strings.TrimPrefix(disk, "model-")
		if name == "" || name == disk || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
			continue
		}
		dir := filepath.Join(root, name)
		if clean == dir || strings.HasPrefix(clean, dir+string(filepath.Separator)) {
			return nil
		}
	}
	return fmt.Errorf(
		"mount source %s is not a model disk assigned to this deployment; an image may mount only its assigned disk",
		source)
}
