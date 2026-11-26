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
	// Only the deployment's own assigned disk (model-<x> at /mnt/<x>), or a
	// path under it.
	assigned := []string{"model-gemma4-31b"}
	for _, s := range []string{"/mnt/gemma4-31b", "/mnt/gemma4-31b/", "/mnt/gemma4-31b/weights"} {
		if err := checkImageMountSource(s, assigned); err != nil {
			t.Errorf("checkImageMountSource(%q, assigned) = %v, want nil", s, err)
		}
	}

	// Never /mnt itself (every disk on the VM), never a sibling disk, never
	// anything outside; "/:/host:rw" was the original case.
	refused := []string{
		"/mnt",
		"/mnt/",
		"/mnt/qwen25-32b",
		"/mnt/gemma4-31b-other",
		"/",
		"/etc",
		"/data",
		"/mnt/../etc",
		"/mntother",
		"relative/path",
		"",
	}
	for _, s := range refused {
		if err := checkImageMountSource(s, assigned); err == nil {
			t.Errorf("checkImageMountSource(%q, assigned) = nil, want error", s)
		}
	}
	// Nothing assigned (every deployment today): every image-declared mount
	// is refused, including the former /mnt label.
	for _, s := range []string{"/mnt", "/mnt/gemma4-31b", "/mnt/model-gemma4-31b"} {
		if err := checkImageMountSource(s, nil); err == nil {
			t.Errorf("checkImageMountSource(%q, nil) = nil, want error", s)
		}
	}
	// A malformed assignment grants nothing.
	for _, bad := range [][]string{{"gemma4-31b"}, {"model-"}, {"model-.."}, {"model-a/b"}} {
		if err := checkImageMountSource("/mnt/gemma4-31b", bad); err == nil {
			t.Errorf("assignment %v granted a mount", bad)
		}
	}
}
