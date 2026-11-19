// Copyright (c) Privasys. All rights reserved.

package manager

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// A monitoring token is read-only: the dependency set and the PROXY
// protocol allow-list are refused to it before the body is read. A manager
// token gets past the role check (here to a 400 on an empty body).
func TestWriteRoutesNeedManagerRole(t *testing.T) {
	s := &Server{log: zap.NewNop()}
	routes := []struct {
		name    string
		method  string
		path    string
		handler http.HandlerFunc
	}{
		{"dependencies", http.MethodPut, "/api/v1/containers/app/dependencies", s.handleSetDependencies},
		{"proxy-protocol", http.MethodPut, "/api/v1/edge/proxy-protocol", s.handleSetProxyProtocol},
	}
	for _, rt := range routes {
		for _, c := range []struct {
			role string
			want int
		}{{"monitoring", http.StatusForbidden}, {"", http.StatusForbidden}, {"manager", http.StatusBadRequest}} {
			r := httptest.NewRequest(rt.method, rt.path, strings.NewReader(""))
			r.SetPathValue("name", "app")
			w := httptest.NewRecorder()
			rt.handler(w, withRole(r, c.role))
			if w.Code != c.want {
				t.Errorf("%s with role %q: status %d, want %d (%s)", rt.name, c.role, w.Code, c.want, w.Body.String())
			}
		}
	}
}
