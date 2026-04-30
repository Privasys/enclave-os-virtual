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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/archive"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
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
	// Strip optional @sha256:... digest suffix used for pin verification.
	if i := strings.Index(name, "@"); i >= 0 {
		name = name[:i]
	}
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
		// containerd's archive.ImportIndex only creates named images
		// for manifest entries that carry an
		// `org.opencontainers.image.ref.name` annotation. Older OCI
		// layouts published by skopeo (and the
		// .operations/scripts/publish-image-disk.sh pipeline) omit
		// it: the blobs are imported but no Image record is created,
		// so we get zero results.
		//
		// Fall back to parsing index.json ourselves and explicitly
		// creating an image record pointing at the manifest entry.
		idx, parseErr := readOCIIndex(dir)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("container: %s contained no images and index.json unreadable: %w", dir, parseErr)
		}
		desc, pickErr := pickPlatformManifest(idx)
		if pickErr != nil {
			return nil, nil, fmt.Errorf("container: %s contained no images: %w", dir, pickErr)
		}
		created, createErr := m.client.ImageService().Create(ctx, images.Image{
			Name:   ref,
			Target: desc,
		})
		if createErr != nil && !errdefs.IsAlreadyExists(createErr) {
			return nil, nil, fmt.Errorf("container: register image %s: %w", ref, createErr)
		}
		if errdefs.IsAlreadyExists(createErr) {
			created, createErr = m.client.ImageService().Get(ctx, ref)
			if createErr != nil {
				return nil, nil, fmt.Errorf("container: get existing image %s: %w", ref, createErr)
			}
		}
		imgs = []images.Image{created}
		m.log.Info("registered image from index.json (no annotations)",
			zap.String("ref", ref),
			zap.String("digest", desc.Digest.String()),
		)
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
			// Tolerate unreadable subtrees that aren't part of the OCI
			// layout (e.g. ext4's root-owned `lost+found` directory on
			// freshly-formatted partitions). Skipping them lets the
			// tar continue with the actual OCI files.
			if info != nil && info.IsDir() {
				rel, _ := filepath.Rel(root, path)
				if isNonOCIEntry(rel) {
					return filepath.SkipDir
				}
			}
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

		// Skip filesystem artefacts that are not part of the OCI image
		// layout (lost+found from mke2fs, snapshot dirs, etc.). We
		// match only at the top level; the OCI spec defines exactly
		// three entries: oci-layout, index.json, blobs/.
		if !strings.Contains(rel, "/") && isNonOCIEntry(rel) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

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

// isNonOCIEntry reports whether a top-level entry name is something
// other than the three names defined by the OCI image layout spec
// (oci-layout, index.json, blobs). Used to filter filesystem
// artefacts like ext4's `lost+found` directory.
func isNonOCIEntry(name string) bool {
	switch name {
	case "oci-layout", "index.json", "blobs", "manifest.json":
		return false
	}
	return true
}

// readOCIIndex parses <dir>/index.json into an OCI image-index struct.
func readOCIIndex(dir string) (*ocispec.Index, error) {
	b, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, err
	}
	var idx ocispec.Index
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("parse index.json: %w", err)
	}
	return &idx, nil
}

// pickPlatformManifest returns the manifest descriptor that best
// matches the host platform. If no entry has a Platform field, the
// first manifest entry is returned (single-platform layouts published
// by skopeo commonly omit the field).
func pickPlatformManifest(idx *ocispec.Index) (ocispec.Descriptor, error) {
	if idx == nil || len(idx.Manifests) == 0 {
		return ocispec.Descriptor{}, errors.New("no manifests in index.json")
	}
	host := platforms.DefaultSpec()
	matcher := platforms.NewMatcher(host)
	var fallback *ocispec.Descriptor
	for i := range idx.Manifests {
		d := idx.Manifests[i]
		if d.Platform == nil {
			if fallback == nil {
				fallback = &idx.Manifests[i]
			}
			continue
		}
		if matcher.Match(*d.Platform) {
			return d, nil
		}
	}
	if fallback != nil {
		return *fallback, nil
	}
	return ocispec.Descriptor{}, fmt.Errorf("no manifest matches host platform %s/%s", host.OS, host.Architecture)
}
