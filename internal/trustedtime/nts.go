package trustedtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/beevik/ntp"
	"github.com/beevik/nts"
)

const (
	// maxRTT rejects NTP replies slower than this. The round trip is measured
	// with Go's monotonic clock, which the guest kernel keeps from the TSC on
	// TDX: the host cannot change it. A host that holds a reply for X seconds
	// could otherwise roll its clock back by X to match it.
	maxRTT = 2 * time.Second

	// agreement is how close two servers must be to count as agreeing.
	agreement = 2 * time.Second

	// keTimeout bounds the NTS key exchange (TCP + TLS 1.3).
	keTimeout = 5 * time.Second
)

// Sample is one NTS quorum result: the estimated true time at the moment the
// quorum returned, and the servers that agreed on it.
type Sample struct {
	Time    time.Time
	Servers []string
}

// NTSSource fetches the time from NTS servers. floor is the lower bound
// server certificates are checked against (the host clock is what is in
// question, so it cannot be used for that).
type NTSSource interface {
	Quorum(ctx context.Context, floor time.Time) (Sample, error)
}

// reading is one server's answer: its estimated time at the monotonic instant
// the reply was received.
type reading struct {
	server string
	est    time.Time // wall time, no monotonic reading
	recv   time.Time // local monotonic instant of receipt
}

// now projects the reading to the current monotonic instant.
func (r reading) now() time.Time { return r.est.Add(time.Since(r.recv)) }

// NTSQuorum queries the pinned NTS servers: two picked at random must agree
// within 2 s; otherwise a third is asked and the majority wins; no majority,
// or too few replies, is an error.
type NTSQuorum struct {
	servers []string
	query   func(ctx context.Context, server string, floor time.Time) (reading, error)
}

// NewNTSQuorum returns a quorum over the compiled server list.
func NewNTSQuorum() *NTSQuorum {
	return &NTSQuorum{servers: NTSServers[:], query: queryNTS}
}

// Quorum implements NTSSource.
func (q *NTSQuorum) Quorum(ctx context.Context, floor time.Time) (Sample, error) {
	if len(q.servers) < 3 {
		return Sample{}, errors.New("nts: fewer than three servers pinned")
	}
	order := rand.Perm(len(q.servers))
	pick := func(i int) string { return q.servers[order[i]] }

	type result struct {
		r   reading
		err error
	}
	// Buffered for all three, so a query still running when the deadline
	// passes can finish without blocking; its result is dropped.
	ch := make(chan result, 3)
	start := func(s string) {
		go func() {
			r, err := q.query(ctx, s, floor)
			ch <- result{r, err}
		}()
	}
	var ok []reading
	var errs []string
	// collect waits for n results or the deadline, whichever comes first:
	// the quorum as a whole never outlives ctx, whatever a server (or the
	// host holding its packets) does.
	collect := func(n int) {
		for i := 0; i < n; i++ {
			select {
			case res := <-ch:
				if res.err != nil {
					errs = append(errs, res.err.Error())
					continue
				}
				ok = append(ok, res.r)
			case <-ctx.Done():
				errs = append(errs, "deadline: "+ctx.Err().Error())
				return
			}
		}
	}
	start(pick(0))
	start(pick(1))
	collect(2)
	if s, found := agreeing(ok); found {
		return s, nil
	}
	// Disagreement or a missing reply: a third server decides, if time is
	// left.
	if ctx.Err() == nil {
		start(pick(2))
		collect(1)
	}
	if s, found := agreeing(ok); found {
		return s, nil
	}
	if len(ok) < 2 {
		return Sample{}, fmt.Errorf("nts: too few replies (%d of 3): %s", len(ok), strings.Join(errs, "; "))
	}
	return Sample{}, fmt.Errorf("nts: no two of %d servers agree within %s", len(ok), agreement)
}

// agreeing looks for two readings within the agreement window and returns
// the earlier of the closest such pair, projected to now. The earlier one is
// taken because the result may raise the floor, which must never overshoot
// real time.
func agreeing(rs []reading) (Sample, bool) {
	type proj struct {
		t      time.Time
		server string
	}
	ps := make([]proj, len(rs))
	for i, r := range rs {
		ps[i] = proj{r.now(), r.server}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].t.Before(ps[j].t) })
	best := -1
	var gap time.Duration
	for i := 0; i+1 < len(ps); i++ {
		d := ps[i+1].t.Sub(ps[i].t)
		if d <= agreement && (best < 0 || d < gap) {
			best, gap = i, d
		}
	}
	if best < 0 {
		return Sample{}, false
	}
	return Sample{Time: ps[best].t.UTC().Round(0), Servers: []string{ps[best].server, ps[best+1].server}}, true
}

// queryNTS runs one NTS key exchange and one authenticated NTP query.
func queryNTS(ctx context.Context, server string, floor time.Time) (reading, error) {
	var d net.Dialer
	opt := &nts.SessionOptions{
		TLSConfig: floorTLSConfig(server, floor),
		Timeout:   within(ctx, keTimeout),
		Dialer: func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
			dctx, cancel := context.WithTimeout(ctx, keTimeout)
			defer cancel()
			conn, err := (&tls.Dialer{NetDialer: &d, Config: cfg}).DialContext(dctx, network, addr)
			if err != nil {
				return nil, err
			}
			return conn.(*tls.Conn), nil
		},
		// Resolve the NTP server named by the key exchange now, so the
		// timed query below does not include a DNS lookup.
		Resolver: func(addr string) string {
			host, port, err := net.SplitHostPort(addr)
			if err != nil || net.ParseIP(host) != nil {
				return addr
			}
			rctx, cancel := context.WithTimeout(ctx, keTimeout)
			defer cancel()
			ips, err := net.DefaultResolver.LookupIPAddr(rctx, host)
			if err != nil || len(ips) == 0 {
				return addr
			}
			return net.JoinHostPort(ips[0].IP.String(), port)
		},
	}
	sess, err := nts.NewSessionWithOptions(server, opt)
	if err != nil {
		return reading{}, fmt.Errorf("%s: key exchange: %w", server, err)
	}
	if err := ctx.Err(); err != nil {
		return reading{}, err
	}
	start := time.Now()
	resp, err := sess.QueryWithOptions(&ntp.QueryOptions{Timeout: within(ctx, maxRTT)})
	recv := time.Now()
	if err != nil {
		return reading{}, fmt.Errorf("%s: query: %w", server, err)
	}
	rtt := recv.Sub(start) // monotonic
	if rtt > maxRTT {
		return reading{}, fmt.Errorf("%s: reply took %s (limit %s)", server, rtt, maxRTT)
	}
	if err := resp.Validate(); err != nil {
		return reading{}, fmt.Errorf("%s: invalid reply: %w", server, err)
	}
	// The server stamped its transmit time about half a round trip ago.
	return reading{server: server, est: resp.Time.UTC().Add(rtt / 2), recv: recv}, nil
}

// floorTLSConfig verifies the NTS-KE server certificate against the floor,
// never the host clock (the host clock is what is in question).
//
// The floor is a lower bound on real time, so it proves a certificate that
// expired before it is expired, but it cannot prove a certificate is already
// valid: NotBefore is checked against the later of the floor and the chain's
// own NotBefore dates. Accepting a certificate "from the future" needs a CA
// to have issued it, which is what the chain check is for; accepting an
// expired one (whose key may have leaked since) is what a rolled-back clock
// would buy, and the floor refuses it.
func floorTLSConfig(server string, floor time.Time) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         server,
		InsecureSkipVerify: true, // replaced by VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyAgainstFloor(cs.PeerCertificates, server, floor, nil)
		},
	}
}

// verifyAgainstFloor checks a presented chain for host with the floor as the
// clock. roots nil means the system roots.
func verifyAgainstFloor(certs []*x509.Certificate, host string, floor time.Time, roots *x509.CertPool) error {
	if len(certs) == 0 {
		return errors.New("nts: server presented no certificate")
	}
	at := floor
	for _, c := range certs {
		if c.NotAfter.Before(floor) {
			return fmt.Errorf("nts: certificate %q expired %s, before the trusted floor %s",
				c.Subject.CommonName, c.NotAfter.UTC().Format(time.RFC3339), floor.UTC().Format(time.RFC3339))
		}
		if c.NotBefore.After(at) {
			at = c.NotBefore
		}
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("nts: certificate of %s: %w", host, err)
	}
	return nil
}

// within returns d, shortened to what is left before ctx's deadline, so no
// single network step outlives the quorum's budget.
func within(ctx context.Context, d time.Duration) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < d {
			if left <= 0 {
				return time.Millisecond
			}
			return left
		}
	}
	return d
}
