// Copyright (c) Privasys. All rights reserved.

package container

import "testing"

func TestIsAllowedImageDevice(t *testing.T) {
	// The devices the one real producer declares
	// (confidential-ai/Dockerfile.prod) all have to keep working.
	allowed := []string{
		"/dev/nvidia0",
		"/dev/nvidia1",
		"/dev/nvidia15",
		"/dev/nvidiactl",
		"/dev/nvidia-uvm",
		"/dev/nvidia-uvm-tools",
	}
	for _, d := range allowed {
		if !isAllowedImageDevice(d) {
			t.Errorf("isAllowedImageDevice(%q) = false, want true", d)
		}
	}

	// The escalation the label used to permit: an image naming any host
	// device and receiving read, write and mknod on it.
	refused := []string{
		"/dev/sda",
		"/dev/mem",
		"/dev/kvm",
		"/dev/nvidia",     // no index, not a real node
		"/dev/nvidia0x",   // suffix past the index
		"/dev/../dev/sda", // traversal
		"/dev/nvidia0/../sda",
		"nvidia0", // relative
		"",
		"/dev/",
	}
	for _, d := range refused {
		if isAllowedImageDevice(d) {
			t.Errorf("isAllowedImageDevice(%q) = true, want false", d)
		}
	}
}

func TestCheckImageMountSource(t *testing.T) {
	// The real producers: the prod image mounts /mnt itself, per-model images
	// mount a subdirectory.
	allowed := []string{
		"/mnt",
		"/mnt/",
		"/mnt/model-gemma4-31b",
		"/mnt/model-qwen25-32b",
	}
	for _, s := range allowed {
		if err := checkImageMountSource(s); err != nil {
			t.Errorf("checkImageMountSource(%q) = %v, want nil", s, err)
		}
	}

	// "/:/host:rw" was the reported case: the whole host filesystem, writable.
	refused := []string{
		"/",
		"/etc",
		"/data",
		"/mnt/../etc",
		"/mntother",
		"relative/path",
		"",
	}
	for _, s := range refused {
		if err := checkImageMountSource(s); err == nil {
			t.Errorf("checkImageMountSource(%q) = nil, want error", s)
		}
	}
}
