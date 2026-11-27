package launcher

import "strings"

// ConfigureGrantEnv tells an app that this runtime strips and sets
// X-Privasys-Configure-Authorized (the manager's configure gate result). Only
// with it may the app trust that header; a runtime without it passes a
// client's copy through untouched.
const ConfigureGrantEnv = "PRIVASYS_CONFIGURE_GRANT"

// stampPlatformEnv writes the platform facts the runtime itself vouches for
// into env, overwriting whatever is there: nothing from the load request or
// host metadata can set the capability marker.
func (l *Launcher) stampPlatformEnv(env map[string]string) {
	// The identity provider this fleet trusts, for spend tokens (the app
	// fetches one per signed-in user from <issuer>/spend/token): the image's
	// pinned issuer. An app verifying tokens still allowlists it in code.
	delete(env, "PRIVASYS_ISSUER")
	if l.cfg.Issuer != "" {
		env["PRIVASYS_ISSUER"] = strings.TrimRight(l.cfg.Issuer, "/")
	}
	// The audience the fleet's tokens carry (one per deployment: the test
	// platform's on dev), pinned like the issuer.
	delete(env, "PRIVASYS_AUDIENCE")
	if l.cfg.Audience != "" {
		env["PRIVASYS_AUDIENCE"] = l.cfg.Audience
	}
	// Compiled in: this build strips and sets the configure grant header.
	env[ConfigureGrantEnv] = "1"
}
