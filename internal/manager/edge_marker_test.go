package manager

import (
	"net/http/httptest"
	"testing"
)

func TestEdgeMarkerAnyCopyAnyCase(t *testing.T) {
	for _, vals := range [][]string{
		{"terminate"}, {"Terminate"}, {" TERMINATE "}, {"direct", "terminate"}, {"x, terminate"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		for _, v := range vals {
			r.Header.Add(edgeHeader, v)
		}
		if !isEdgeTerminated(r) {
			t.Errorf("%q: not read as the terminate leg", vals)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add(edgeHeader, "Direct")
	if !isDirectLeg(r) || isEdgeTerminated(r) {
		t.Error("Direct: wrong leg")
	}
	if isEdgeTerminated(httptest.NewRequest("GET", "/", nil)) {
		t.Error("no marker read as terminate")
	}
}
