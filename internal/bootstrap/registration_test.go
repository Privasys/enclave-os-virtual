package bootstrap

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestOpenSealedPayloadRoundTrip(t *testing.T) {
	epk, esk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want := sealedRegistrationPayload{
		EnclaveID:  "11111111-2222-3333-4444-555555555555",
		Credential: "cred-abc",
		CACert:     "CERT",
		CAKey:      "KEY",
		ManagerEnv: map[string]string{"MGMT_URL": "https://api-test"},
	}
	plain, _ := json.Marshal(want)
	sealed, err := box.SealAnonymous(nil, plain, epk, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openSealedPayload(base64.StdEncoding.EncodeToString(sealed), epk, esk)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.EnclaveID != want.EnclaveID || got.Credential != want.Credential ||
		got.CACert != want.CACert || got.CAKey != want.CAKey {
		t.Fatalf("payload mismatch: %+v", got)
	}

	// Wrong recipient key must not open.
	epk2, esk2, _ := box.GenerateKey(rand.Reader)
	if _, err := openSealedPayload(base64.StdEncoding.EncodeToString(sealed), epk2, esk2); err == nil {
		t.Fatal("sealed payload opened with the wrong key")
	}
}

func TestOpenSealedPayloadRejectsIncomplete(t *testing.T) {
	epk, esk, _ := box.GenerateKey(rand.Reader)
	plain, _ := json.Marshal(sealedRegistrationPayload{CACert: "CERT"}) // no key/credential
	sealed, _ := box.SealAnonymous(nil, plain, epk, rand.Reader)
	if _, err := openSealedPayload(base64.StdEncoding.EncodeToString(sealed), epk, esk); err == nil {
		t.Fatal("incomplete payload accepted")
	}
}

func TestRegistrationListenerTokenCheck(t *testing.T) {
	tokenCh := make(chan string, 1)
	resultCh := make(chan registrationResult, 1)
	h := registrationListener(tokenCh, resultCh)
	tokenCh <- "good-token"

	post := func(body string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/registration-result", bytes.NewReader([]byte(body)))
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := post(`{"status":"approved","callback_token":"wrong"}`); code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", code)
	}
	if code := post(`{"status":"approved","callback_token":"good-token","sealed":"x"}`); code != http.StatusOK {
		t.Fatalf("good token: got %d, want 200", code)
	}
	select {
	case res := <-resultCh:
		if res.Status != "approved" {
			t.Fatalf("result status %q", res.Status)
		}
	default:
		t.Fatal("result not delivered")
	}
}

func TestReadEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manager.env")
	content := "# comment\nMGMT_URL=https://api-test\nENCLAVE_ID = abc \n\nBAD-LINE\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	env, err := readEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if env["MGMT_URL"] != "https://api-test" || env["ENCLAVE_ID"] != "abc" {
		t.Fatalf("parsed: %+v", env)
	}
}
