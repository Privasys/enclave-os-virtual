package directtls

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// A name an app releases takes its certificate with it, so the next owner
// never serves the previous app's certificate (certificates are stored by CA
// and name, not by app). An unload is not a release: the certificate stays
// for the same app's next load. A name whose marker belongs to another app
// is purged before it is taken.
func TestReleasedNameTakesItsCertificate(t *testing.T) {
	root, err := os.MkdirTemp("", "directtls")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	s := New(Config{StorageRoot: root, CA: "https://127.0.0.1:1/directory"}, zap.NewNop())
	key, _ := AccountKey([]byte("branch-of-app-one-volume-key-000"))
	other, _ := AccountKey([]byte("branch-of-app-two-volume-key-000"))
	siteDir := func(name string) string {
		return filepath.Join(root, filepath.FromSlash(certmagic.StorageKeys.CertsSitePrefix(s.issuerKey, name)))
	}
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }

	if err := s.Apply("drive", "drive.apps.example.org", []string{"a.example.com", "b.example.com"}, key); err != nil {
		t.Fatal(err)
	}
	writeLeaf(t, s, "a.example.com")
	writeLeaf(t, s, "b.example.com")

	// An unload keeps both certificates.
	s.Remove("drive")
	if !exists(siteDir("a.example.com")) || !exists(siteDir("b.example.com")) {
		t.Fatal("an unload purged a certificate")
	}

	// The app comes back and its policy drops b: b's certificate goes.
	if err := s.Apply("drive", "drive.apps.example.org", []string{"a.example.com", "b.example.com"}, key); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply("drive", "drive.apps.example.org", []string{"a.example.com"}, key); err != nil {
		t.Fatal(err)
	}
	if exists(siteDir("b.example.com")) {
		t.Fatal("a released name kept its certificate")
	}
	if !exists(siteDir("a.example.com")) {
		t.Fatal("a kept name lost its certificate")
	}

	// Another app taking a name whose marker is still drive's purges first.
	if err := s.Apply("mail", "mail.apps.example.org", []string{"a.example.com"}, other); err != nil {
		t.Fatal(err)
	}
	defer s.Remove("mail")
	defer s.Remove("drive")
	if exists(siteDir("a.example.com")) {
		t.Fatal("a name taken over another app's marker kept that app's certificate")
	}
}
