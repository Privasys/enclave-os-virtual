package manager

import (
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestConsentRefusal(t *testing.T) {
	if msg := consentRefusal("5000 credits", "5000 credits"); msg != "" {
		t.Fatalf("exact match must pass, got %q", msg)
	}
	missing := consentRefusal("5000 credits", "")
	if missing != "payment approval required: this call charges 5000 credits — retry with X-Billing-Approved: 5000 credits" {
		t.Fatalf("unexpected missing-consent message: %q", missing)
	}
	// Approving MORE than the price still fails: the point is proof the
	// caller knew this exact price.
	mismatch := consentRefusal("5000 credits", "10000 credits")
	if mismatch != "payment approval mismatch: approved '10000 credits' but this call charges 5000 credits — retry with X-Billing-Approved: 5000 credits" {
		t.Fatalf("unexpected mismatch message: %q", mismatch)
	}
	// Clients regex the current attested price out of the refusal; the
	// caller's wrong figure must never be what the anchor finds.
	priceRE := regexp.MustCompile(`charges (\d+) credits`)
	m := priceRE.FindStringSubmatch(mismatch)
	if len(m) != 2 || m[1] != "5000" {
		t.Fatalf("price anchor read %v from %q", m, mismatch)
	}
}

func TestBilledResponseWriterStampsCharge(t *testing.T) {
	rec := httptest.NewRecorder()
	bw := &billedResponseWriter{ResponseWriter: rec, charged: "5000 credits"}
	bw.WriteHeader(200)
	if got := rec.Header().Get("X-Billing-Charged"); got != "5000 credits" {
		t.Fatalf("X-Billing-Charged = %q", got)
	}
	if bw.status != 200 {
		t.Fatalf("status = %d", bw.status)
	}
}

func TestBilledResponseWriterNoChargeOnFailure(t *testing.T) {
	rec := httptest.NewRecorder()
	bw := &billedResponseWriter{ResponseWriter: rec, charged: "5000 credits"}
	bw.WriteHeader(500)
	if got := rec.Header().Get("X-Billing-Charged"); got != "" {
		t.Fatalf("failed call must not claim a charge, got %q", got)
	}
	if bw.status != 500 {
		t.Fatalf("status = %d", bw.status)
	}
}

func TestBilledResponseWriterImplicitOK(t *testing.T) {
	rec := httptest.NewRecorder()
	bw := &billedResponseWriter{ResponseWriter: rec, charged: "7 credits"}
	if _, err := bw.Write([]byte("body")); err != nil {
		t.Fatal(err)
	}
	if got := rec.Header().Get("X-Billing-Charged"); got != "7 credits" {
		t.Fatalf("implicit 200 must stamp the charge, got %q", got)
	}
	if bw.status != 200 {
		t.Fatalf("status = %d", bw.status)
	}
}
