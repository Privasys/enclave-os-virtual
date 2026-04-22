// Disk-backed image pulls.
//
// When a container manifest references its image as
//
//	disk://<image-name>-<channel>
//
// the manager treats it as already-present on a locally mounted GCE
// persistent disk under
//
//	/var/lib/images/<image-name>-<channel>/
//
// (see disk-mounter.service in build/image-gpu). The directory is
// the root of an OCI image layout (oci-layout, index.json,
// blobs/sha256/...). No network
// pull happens. Instead, the OCI layout is streamed as a tar to
// containerd's Import API, which ingests blobs into the content store
// and then unpacks the image into the snapshotter.
//
// The disk is mounted read-only and may be shared between concurrent
// VMs. We never write back to it.

package container

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images/archive"
	"github.com/containerd/platforms"
	"go.uber.org/zap"
)

// DiskImageRoot is the directory under which disk-mounter.service
// mounts image disks. Each subdirectory is the root of an OCI image
// layout for a single (image, channel) pair.
const DiskImageRoot = "/var/lib/images"

// IsDiskRef reports whether ref uses the disk:// scheme.
func IsDiskRef(ref string) bool {
	return strings.HasPrefix(ref, "disk://")
}

// diskRefDir resolves a disk:// ref to a filesystem directory under
// DiskImageRoot. The ref form is disk://<name>; <name> may contain
// '/' (for fully qualified image names) but the result must remain
// inside DiskImageRoot.
func diskRefDir(ref string) (string, error) {
	if !IsDiskRef(ref) {
		return "", fmt.Errorf("container: not a disk ref: %s", ref)
	}
	name := strings.TrimPrefix(ref, "disk://")
	if name == "" {
		return "", fmt.Errorf("container: empty disk ref")
	}
	// Reject parent-traversal early.
	if strings.Contains(name, "..") {
		return "", fmt.Errorf("container: disk ref must not contain '..': %s", ref)
	}
	dir := filepath.Join(DiskImageRoot, name)
	// Defence in depth: ensure the cleaned path is still under
	// DiskImageRoot.
	cleanRoot := filepath.Clean(DiskImageRoot) + string(filepath.Separator)
	if !strings.HasPrefix(filepath.Clean(dir)+string(filepath.Separator), cleanRoot) {
		return "", fmt.Errorf("container: disk ref escapes %s: %s", DiskImageRoot, ref)
	}
	return dir, nil
}

// importFromDisk imports an OCI image layout from dir into the
// containerd content store, names the image as the disk ref, unpacks
// it into the default snapshotter, and returns the image plus its
// resolved digest bytes.
func (m *Manager) importFromDisk(ctx context.Context, ref, dir string) (client.Image, []byte, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("container: disk image dir %s: %w", dir, err)
	}
	if !st.IsDir() {
		return nil, nil, fmt.Errorf("container: disk image path %s is not a directory", dir)
	}
	// Sanity: oci-layout must exist (every OCI image layout has it).
	if _, err := os.Stat(filepath.Join(dir, "oci-layout")); err != nil {
		return nil, nil, fmt.Errorf("container: %s is not an OCI image layout (missing oci-layout): %w", dir, err)
	}

	// Stream the directory as a tar into client.Import via a pipe.
	pr, pw := io.Pipe()
	go func() {
		err := tarOCILayout(dir, pw)
		// Close the writer with the error so Import sees EOF cleanly
		// or aborts on tar failure.
		_ = pw.CloseWithError(err)
	}()

	imgs, err := m.client.Import(ctx, pr,
		// Name every image we find with the ref the user asked for,
		// so a subsequent GetImage(ref) finds it.
		client.WithImageRefTranslator(archive.AddRefPrefix(ref)),
		// The disk may legitimately omit foreign-platform manifest
		// blobs (we publish single-platform OCI layouts). Don't error
		// on missing referenced blobs.
		client.WithSkipMissing(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("container: import from %s: %w", dir, err)
	}
	if len(imgs) == 0 {
		return nil, nil, fmt.Errorf("container: %s contained no images", dir)
	}

	// Pick the first image whose target matches the host platform.
	// Import returns one entry per name in index.json plus the index
	// itself; the AddRefPrefix translator gives them the same name
	// prefix so pick the first.
	var chosen *client.Image
	for i := range imgs {
		img := client.NewImageWithPlatform(m.client, imgs[i], platforms.Default())
		chosen = &img
		break
	}
	if chosen == nil {
		return nil, nil, fmt.Errorf("container: %s contained no usable image for host platform", dir)
	}

	// Unpack into the default snapshotter so Create() can build a
	// container off it. WithPullUnpack (used by the registry path) does
	// this automatically; the Import API doesn't, so we do it here.
	if err := (*chosen).Unpack(ctx, ""); err != nil {
		return nil, nil, fmt.Errorf("container: unpack %s: %w", ref, err)
	}

	resolvedDigest := (*chosen).Target().Digest.String()
	digestBytes, err := digestToBytes(resolvedDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("container: parse digest from disk image %s: %w", ref, err)
	}
	m.log.Info("image imported from disk",
		zap.String("ref", ref),
		zap.String("dir", dir),
		zap.String("digest", resolvedDigest),
	)
	return *chosen, digestBytes, nil
}

// tarOCILayout writes dir (an OCI image layout) into w as an
// uncompressed tar, suitable for containerd's archive.ImportIndex.
// Symlinks are followed (we only ever publish regular files in the
// publish-gcp-disk workflow).
func tarOCILayout(dir string, w io.Writer) error {
	tw := tar.NewWriter(w)
	defer tw.Close()

	root := filepath.Clean(dir)
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip the top-level dir itself.
		if path == root {
			return nil
		}
		// Tar header name: path relative to root, forward slashes.
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		switch {
		case info.IsDir():
			hdr := &tar.Header{
				Typeflag: tar.TypeDir,
				Name:     rel + "/",
				Mode:     0o755,
				ModTime:  info.ModTime(),
			}
			return tw.WriteHeader(hdr)
		case info.Mode().IsRegular():
			hdr := &tar.Header{
				Typeflag: tar.TypeReg,
				Name:     rel,
				Size:     info.Size(),
				Mode:     0o644,
				ModTime:  info.ModTime(),
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tw, f)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		default:
			// Skip symlinks, devices, etc. - the publish-gcp-disk
			// workflow never writes any of these into the layout.
			return nil
		}
	})
}
