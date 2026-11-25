package manager

import (
	"net/http"
	"strings"

	"github.com/Privasys/enclave-os-virtual/internal/surfaces"
)

// The holder-facing paths on an app's hostname (capabilities, and the
// window onto the holder's folder) belong to the enclave OS. A caller
// presents the holder's own bearer there, so they never fall through to the
// app: an app that declares no resources answers 404 here, and its
// container receives nothing.

// underEither reports whether p, as sent OR resolved, is under prefix. The
// opposite of surfaces.UnderPrefix (both forms, for an exemption): here a
// match keeps the request from the app, so either form is enough, and a dot
// segment cannot carry a holder path past this check to the container.
func underEither(p, prefix string) bool {
	one := func(q string) bool { return q == prefix || strings.HasPrefix(q, prefix+"/") }
	return one(p) || one(surfaces.CanonicalPath(p))
}

// holderContainerFor is the container serving host and how many resources it
// declares. Tests replace it through Server.holderResourcesOf.
func (s *Server) holderContainerFor(host string) (string, int) {
	if s.holderResourcesOf != nil {
		return s.holderResourcesOf(host)
	}
	if s.launcher == nil {
		return "", 0
	}
	name := s.launcher.AppHostnameToContainer(host)
	if name == "" {
		return "", 0
	}
	return name, len(s.launcher.ContainerResourceDecls(name))
}

// serveEnclaveHolderPaths answers a holder path on an app host, and reports
// whether it did. It never hands the request to the app.
func (s *Server) serveEnclaveHolderPaths(w http.ResponseWriter, r *http.Request, host string) bool {
	caps := underEither(r.URL.Path, holderCapabilitiesPath)
	files := !caps && underEither(r.URL.Path, holderFilesPath)
	if !caps && !files {
		return false
	}
	name, decls := s.holderContainerFor(host)
	switch {
	case name == "" || decls == 0:
		s.jsonError(w, http.StatusNotFound, "this app keeps nothing for its holders")
	case caps:
		s.serveHolderCapabilities(w, r, name)
	default:
		s.serveHolderFiles(w, r, name)
	}
	return true
}
