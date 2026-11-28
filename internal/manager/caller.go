package manager

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// caller is what one request presents, each credential verified at most
// once however many gates read it: the route gate, the configure gate, the
// tool-subject assertion and the fee gate all ask for the same facts.
//
// It reads Authorization and X-App-Auth as they are when it is first asked.
// The dispatcher installs it after the leg is decided (a direct name takes
// its bearer out, the clear leg strips credentials), and nothing changes
// those headers afterwards.
type caller struct {
	s *Server
	r *http.Request

	platformDone bool
	platform     *auth.Claims
	platformErr  error

	payerDone bool
	payer     *auth.Claims

	toolDone bool
	tool     *auth.Claims
}

type callerKey struct{}

// withCaller installs a fresh caller on r.
func (s *Server) withCaller(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), callerKey{}, &caller{s: s, r: r}))
}

// callerOf is the request's caller: the one the dispatcher installed, or a
// new one for a request that did not come through it.
func (s *Server) callerOf(r *http.Request) *caller {
	if c, ok := r.Context().Value(callerKey{}).(*caller); ok {
		return c
	}
	return &caller{s: s, r: r}
}

// Platform is the Authorization bearer verified for the platform audience.
// The gates that need a platform bearer (owner and role routes, configure,
// the holder paths) read only this.
func (c *caller) Platform() (*auth.Claims, error) {
	if !c.platformDone {
		c.platformDone = true
		c.platform, c.platformErr = c.verifyPlatform(bearerToken(c.r.Header.Get("Authorization")))
	}
	return c.platform, c.platformErr
}

// PlatformPayer is the platform bearer that pays for a call: the
// Authorization bearer when there is one, otherwise X-App-Auth.
func (c *caller) PlatformPayer() *auth.Claims {
	if !c.payerDone {
		c.payerDone = true
		if bearerToken(c.r.Header.Get("Authorization")) != "" {
			c.payer, _ = c.Platform()
		} else {
			c.payer, _ = c.verifyPlatform(strings.TrimSpace(c.r.Header.Get("X-App-Auth")))
		}
	}
	return c.payer
}

// Tool is a verified TOOL token for the app on this host (auth.ToolFor),
// from Authorization or else X-App-Auth, or nil.
func (c *caller) Tool() *auth.Claims {
	if !c.toolDone {
		c.toolDone = true
		appHex := launcher.AppIDHex(c.s.appID(hostOnly(c.r.Host)))
		if c.s.verifier == nil || appHex == "" {
			return nil
		}
		for _, tok := range []string{bearerToken(c.r.Header.Get("Authorization")), strings.TrimSpace(c.r.Header.Get("X-App-Auth"))} {
			if tok == "" {
				continue
			}
			if t, err := c.s.verifier.Verify(tok, auth.ToolFor(appHex)); err == nil {
				c.tool = t
				break
			}
		}
	}
	return c.tool
}

func (c *caller) verifyPlatform(tok string) (*auth.Claims, error) {
	if c.s.verifier == nil {
		return nil, errors.New("no token verifier configured")
	}
	if tok == "" {
		return nil, errors.New("missing bearer token")
	}
	cl, err := c.s.verifier.Verify(tok, c.s.verifier.PlatformAudience())
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	return cl, nil
}

// appID is the platform app id of the container serving host, or "".
func (s *Server) appID(host string) string {
	if s.appIDOf != nil {
		return s.appIDOf(host)
	}
	if s.launcher == nil {
		return ""
	}
	name := s.launcher.AppHostnameToContainer(host)
	if name == "" {
		return ""
	}
	return s.launcher.ContainerFreezeState(name).AppID
}
