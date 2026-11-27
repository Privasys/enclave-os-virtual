// Copyright (c) Privasys. All rights reserved.

package container

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// nvidiaNumberedDevice matches the per-GPU character devices, /dev/nvidia0,
// /dev/nvidia1 and so on.
var nvidiaNumberedDevice = regexp.MustCompile(`^/dev/nvidia[0-9]+$`)

// nvidiaFixedDevices are the NVIDIA control nodes a GPU container needs
// alongside the numbered devices. There is no /dev/nvidia-caps entry:
// containerd expands a directory into every device beneath it.
var nvidiaFixedDevices = map[string]bool{
	"/dev/nvidiactl":        true,
	"/dev/nvidia-uvm":       true,
	"/dev/nvidia-uvm-tools": true,
	"/dev/nvidia-modeset":   true,
}

// isAllowedDevice reports whether a container may be granted this host
// device: a GPU node, nothing else. Each device is granted read, write and
// mknod, and the list comes from the app's deployment, which its owner
// writes, so a disk or /dev/mem must never reach it.
func isAllowedDevice(path string) bool {
	if path != filepath.Clean(path) || !strings.HasPrefix(path, "/dev/") {
		return false
	}
	return nvidiaFixedDevices[path] || nvidiaNumberedDevice.MatchString(path)
}

// checkDevices returns the host devices a container gets, each once, and
// refuses the load if any is not a GPU node.
func checkDevices(name string, requested []string) ([]string, error) {
	var devices []string
	seen := map[string]bool{}
	for _, d := range requested {
		if !isAllowedDevice(d) {
			return nil, fmt.Errorf("container: %s requests host device %q, which is not a GPU device node", name, d)
		}
		if !seen[d] {
			seen[d] = true
			devices = append(devices, d)
		}
	}
	return devices, nil
}

// ImageVolumeLabel is the label an image declares its own host mount with.
const ImageVolumeLabel = "ai.privasys.volume"

// checkImageVolume refuses an image that declares its own host mount. The
// control plane turns the label into a request volume, which the runtime
// mounts as given, and no model disk is assigned to a deployment yet: nothing
// could say which disk the image may have, so a label of "/mnt" would reach
// every model disk on the host. A mount an app needs comes from its
// deployment's own volumes until disks are assigned.
func checkImageVolume(name string, labels map[string]string) error {
	if v, ok := labels[ImageVolumeLabel]; ok {
		return fmt.Errorf("container: %s declares its own host mount (%s=%q); no model disk is assigned to this deployment, so none is mounted", name, ImageVolumeLabel, v)
	}
	return nil
}
