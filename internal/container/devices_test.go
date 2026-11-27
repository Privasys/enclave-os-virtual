// Copyright (c) Privasys. All rights reserved.

package container

import (
	"reflect"
	"testing"
)

func TestIsAllowedDevice(t *testing.T) {
	// The devices GPU apps request today all keep working.
	for _, d := range []string{
		"/dev/nvidia0",
		"/dev/nvidia1",
		"/dev/nvidia15",
		"/dev/nvidiactl",
		"/dev/nvidia-uvm",
		"/dev/nvidia-uvm-tools",
		"/dev/nvidia-modeset",
	} {
		if !isAllowedDevice(d) {
			t.Errorf("isAllowedDevice(%q) = false, want true", d)
		}
	}
	for _, d := range []string{
		"/dev/sda",
		"/dev/mem",
		"/dev/kvm",
		"/dev/nvidia-caps", // a directory: containerd would grant everything under it
		"/dev/nvidia",      // no index, not a real node
		"/dev/nvidia0x",    // suffix past the index
		"/dev/../dev/sda",  // traversal
		"/dev/nvidia0/../sda",
		"nvidia0", // relative
		"",
		"/dev/",
	} {
		if isAllowedDevice(d) {
			t.Errorf("isAllowedDevice(%q) = true, want false", d)
		}
	}
}

func TestCheckDevicesGrantsEachGPUNodeOnceAndRefusesTheRest(t *testing.T) {
	got, err := checkDevices("app", []string{"/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia0"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/dev/nvidia0", "/dev/nvidiactl"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if _, err := checkDevices("app", []string{"/dev/nvidia0", "/dev/sda"}); err == nil {
		t.Fatal("a disk was granted")
	}
	if got, err := checkDevices("app", nil); err != nil || got != nil {
		t.Fatalf("no devices: %v %v", got, err)
	}
}

// An image naming its own host mount is refused, whatever it names: no disk
// is assigned to a deployment, so none can be checked against it.
func TestImageDeclaredVolumeIsRefused(t *testing.T) {
	for _, v := range []string{"/mnt:/models:ro", "/mnt/model-x:/models:ro", "/:/host:rw", ""} {
		if checkImageVolume("app", map[string]string{ImageVolumeLabel: v}) == nil {
			t.Fatalf("%q was accepted", v)
		}
	}
	if err := checkImageVolume("app", map[string]string{"org.privasys.manifest": "{}"}); err != nil {
		t.Fatal(err)
	}
	if err := checkImageVolume("app", nil); err != nil {
		t.Fatal(err)
	}
}
