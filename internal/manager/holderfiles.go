package manager

// The holder's window onto their folder: a file API on the app host, for
// the holder and whoever acts for them with their own credential (their
// wallet, their Drive forwarding their session token). Read and delete, no
// write: what is written there is the app's work, under the holder's key,
// and the app writes it through its worker; a person tidies and takes copies.
//
//	GET    /__privasys/v1/holders/files?path=<rel>   a directory listing (JSON) or a file's bytes
//	DELETE /__privasys/v1/holders/files?path=<rel>   remove a file or a directory tree
//
// The bearer names the holder (holderCaller, as for the mint and the list).
// The folder must be theirs on this app (a usable app_storage grant) and
// open, which an unattended app's is; a folder that is closed is opened from
// the wrapped copy when there is one, and not otherwise. The path is
// confined to the folder: cleaned, no "..", and the resolved path must stay
// under it, so a symlink an app planted cannot lead outside.

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/holders"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

const holderFilesPath = "/__privasys/v1/holders/files"

// serveHolderFiles answers the window on the app host.
func (s *Server) serveHolderFiles(w http.ResponseWriter, r *http.Request, container string) {
	sub, _, ok := s.holderCaller(w, r)
	if !ok {
		return
	}
	appID := s.launcher.ContainerFreezeState(container).AppID
	if appID == "" {
		s.jsonError(w, http.StatusServiceUnavailable, "container has no platform app id")
		return
	}
	resource, decl, ok := s.holderResource(container)
	if !ok {
		s.jsonError(w, http.StatusNotFound, "this app keeps no working files for its holders")
		return
	}
	g := s.caps.granted(appID, resource, sub)
	if !g.usable() || g.HolderKey == "" || g.Kind != launcher.AppStorageKind {
		s.jsonError(w, http.StatusNotFound, "no folder for that holder")
		return
	}
	hf, err := s.launcher.HolderFolders(container)
	if err != nil {
		s.jsonError(w, http.StatusNotImplemented, err.Error())
		return
	}
	if err := s.ensureHolderOpen(container, appID, resource, sub, g, hf); err != nil {
		s.jsonError(w, http.StatusConflict, err.Error())
		return
	}
	root := holders.FolderPath(hf.Mount, g.HolderKey)
	target, rel, err := confineToFolder(root, r.URL.Query().Get("path"))
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.serveHolderFileGet(w, r, root, target, rel, decl.Label)
	case http.MethodDelete:
		if rel == "" {
			s.jsonError(w, http.StatusBadRequest, "the folder itself is not deleted here; revoke the capability")
			return
		}
		if err := os.RemoveAll(target); err != nil {
			s.jsonError(w, http.StatusInternalServerError, "could not delete")
			return
		}
		s.log.Info("holder file deleted", zap.String("container", container), zap.String("holder", g.HolderKey), zap.String("path", rel))
		s.writeJSON(w, http.StatusOK, map[string]any{"deleted": rel})
	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "GET or DELETE")
	}
}

// holderResource is the app's app_storage declaration, when it has one.
func (s *Server) holderResource(container string) (string, capabilityDecl, bool) {
	for _, d := range s.launcher.ContainerResourceDecls(container) {
		if d.Kind == launcher.AppStorageKind {
			decl, ok := s.resourceDecl(container, d.Name)
			return d.Name, decl, ok
		}
	}
	return "", capabilityDecl{}, false
}

// ensureHolderOpen makes sure the holder's key is loaded, from the wrapped
// copy when the folder is closed and the app works unattended.
func (s *Server) ensureHolderOpen(container, appID, resource, sub string, g *capabilityGrant, hf launcher.HolderFolders) error {
	key := grantKey(appID, resource, sub)
	if st, open := s.holdersOpen.get(key); open {
		if ks, err := holders.KeyStatus(hf.Mount, st.KeyID); err == nil && ks == holders.Present {
			return nil
		}
		s.holdersOpen.drop(key)
	}
	if g.WrappedKey == "" {
		return errors.New("the folder is closed and its key is not kept here; open the app first")
	}
	raw, err := unwrapKey(hf.WrapKey, g.WrappedKey, g.HolderKey+"|"+g.CapabilityID)
	if err != nil {
		return errors.New("the stored key could not be unwrapped")
	}
	keyID, err := holders.Open(hf.Mount, g.HolderKey, raw, -1)
	zeroBytes(raw)
	if err != nil {
		return errors.New("the folder could not be opened")
	}
	s.holdersOpen.set(key, holderOpenState{KeyID: keyID, HostUID: -1, OpenedAt: time.Now().UTC()})
	s.events.emit(container, resourceEvent{Type: "holder.opened", Resource: resource, Subject: sub, CapabilityID: g.CapabilityID})
	return nil
}

// confineToFolder resolves a holder-relative path inside root, refusing
// anything that leaves it, symlinks included. Returns the absolute target
// and the cleaned relative path ("" for the root).
func confineToFolder(root, rel string) (string, string, error) {
	rel = strings.TrimPrefix(path.Clean("/"+strings.ReplaceAll(rel, "\\", "/")), "/")
	if rel == "." {
		rel = ""
	}
	target := filepath.Join(root, filepath.FromSlash(rel))
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", errors.New("no such path")
		}
		return "", "", errors.New("path cannot be resolved")
	}
	rootResolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", errors.New("folder cannot be resolved")
	}
	if resolved != rootResolved && !strings.HasPrefix(resolved, rootResolved+string(filepath.Separator)) {
		return "", "", errors.New("path leaves the folder")
	}
	return resolved, rel, nil
}

// serveHolderFileGet lists a directory as JSON or streams a file.
func (s *Server) serveHolderFileGet(w http.ResponseWriter, r *http.Request, root, target, rel, label string) {
	fi, err := os.Stat(target)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, "no such path")
		return
	}
	if !fi.IsDir() {
		f, err := os.Open(target)
		if err != nil {
			s.jsonError(w, http.StatusNotFound, "cannot open")
			return
		}
		defer f.Close()
		ct := mime.TypeByExtension(filepath.Ext(target))
		if ct == "" {
			ct = "application/octet-stream"
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(target)}))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.ServeContent(w, r, filepath.Base(target), fi.ModTime(), f)
		return
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "cannot list")
		return
	}
	type entry struct {
		Name     string `json:"name"`
		Dir      bool   `json:"dir"`
		Size     int64  `json:"size"`
		Modified string `json:"modified"`
	}
	out := make([]entry, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		size := info.Size()
		if e.IsDir() {
			size = 0
		}
		out = append(out, entry{Name: e.Name(), Dir: e.IsDir(), Size: size, Modified: info.ModTime().UTC().Format(time.RFC3339)})
	}
	used, _ := dirSize(root)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"label":      label,
		"path":       rel,
		"entries":    out,
		"used_bytes": used,
	})
}

// dirSize sums the sizes under dir.
func dirSize(dir string) (int64, error) {
	var n int64
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil {
			n += info.Size()
		}
		return nil
	})
	return n, err
}
