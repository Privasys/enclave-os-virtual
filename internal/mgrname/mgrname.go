// Package mgrname derives the hostname the control plane gives an enclave's
// manager: <enclave name>-mgr.<app domain>. The gateway routes that name to
// the manager, so the runtime stamps the platform extensions on its
// certificate (launcher.writePlatformExtensions). The derivation must equal
// the control plane's managerHostname (management-service
// enclave_quarantine.go) byte for byte; the test carries its vectors.
//
// CHANGE BOTH TOGETHER: this function and the control plane's
// managerHostname are one contract, and the shared test vectors
// (mgrname_test.go here, enclave_quarantine_test.go there) are its
// definition. A change on one side without the other leaves a manager whose
// certificate the clients refuse.
package mgrname

import "strings"

// ManagerHostname returns <label>-mgr.<appDomain> for the enclave named
// enclaveName, or "" when either is unusable. A name that already makes a
// valid DNS label is kept exactly (case included); any other is slugged.
func ManagerHostname(enclaveName, appDomain string) string {
	if appDomain == "" {
		return ""
	}
	label := enclaveName + "-mgr"
	if !isDNSLabel(label) {
		slug := dnsSlug(enclaveName)
		if slug == "" {
			return ""
		}
		label = slug + "-mgr"
		if !isDNSLabel(label) {
			return ""
		}
	}
	host := label + "." + appDomain
	if len(host) > 253 {
		return ""
	}
	return host
}

// isDNSLabel reports whether s is a valid DNS label for a hostname: 1 to 63
// letters, digits or hyphens, not starting or ending with a hyphen.
func isDNSLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// dnsSlug lowers name and turns every run of characters that may not appear
// in a DNS label into one hyphen, trimming hyphens at both ends and leaving
// room for the "-mgr" suffix within the 63-byte label limit.
func dnsSlug(name string) string {
	var b strings.Builder
	pendingHyphen := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			if pendingHyphen && b.Len() > 0 {
				b.WriteByte('-')
			}
			pendingHyphen = false
			b.WriteRune(r)
		default:
			pendingHyphen = true
		}
	}
	slug := b.String()
	if max := 63 - len("-mgr"); len(slug) > max {
		slug = strings.TrimRight(slug[:max], "-")
	}
	return slug
}
