// Package egress enforces an exact-origin outbound network policy.
//
// Origins are allow-listed individually (scheme, host, port). Every hostname is
// resolved by the policy itself, every answer is classified before any
// connection is attempted, and connections are made to the vetted numeric
// address only. Errors never carry hosts, addresses or raw causes.
package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors. Callers match with errors.Is; none carry origin details.
var (
	ErrDenied   = errors.New("egress: denied")
	ErrResolve  = errors.New("egress: resolution failed")
	ErrConnect  = errors.New("egress: connection failed")
	ErrResponse = errors.New("egress: invalid response")
	ErrTooLarge = errors.New("egress: response too large")
)

const (
	maxDestinations    = 1024
	maxPrivatePerEntry = 16
	maxResolvedAnswers = 16
	maxHostLen         = 253
	maxLabelLen        = 63
)

// resolver is private to the package so it cannot be replaced through global
// state. StrictErrors makes a temporary failure in one address family fail the
// whole lookup instead of silently shrinking the answer set.
var resolver = &net.Resolver{PreferGo: true, StrictErrors: true}

// Destination is one allowed origin. Port 0 selects the default for
// http/https/ws/wss; tcp and tls require an explicit port. PrivateIPs lists
// exact RFC1918, ULA or CGNAT addresses the host may resolve to.
type Destination struct {
	Scheme     string
	Host       string
	Port       uint16
	PrivateIPs []netip.Addr
}

// Limits bound a single exchange.
type Limits struct {
	Timeout      time.Duration
	MaxBodyBytes int64
}

type target struct {
	scheme, host string
	port         uint16
}

// Policy authorizes, resolves and dials allow-listed origins only.
type Policy struct {
	limits     Limits
	lookupIP   func(context.Context, string) ([]netip.Addr, error)
	dialTCP    func(context.Context, string, string) (net.Conn, error)
	httpClient http.Client

	allowed map[target]map[netip.Addr]struct{}
}

// New validates the destinations and limits and returns a Policy.
func New(destinations []Destination, limits Limits) (*Policy, error) {
	if limits.Timeout <= 0 {
		return nil, errors.New("egress: timeout must be positive")
	}
	if limits.MaxBodyBytes <= 0 {
		return nil, errors.New("egress: max body bytes must be positive")
	}
	if len(destinations) == 0 {
		return nil, errors.New("egress: no destinations")
	}
	if len(destinations) > maxDestinations {
		return nil, errors.New("egress: too many destinations")
	}
	allowed := make(map[target]map[netip.Addr]struct{}, len(destinations))
	for i := range destinations {
		d := destinations[i]
		scheme := d.Scheme
		if scheme != strings.ToLower(scheme) || !validScheme(scheme) {
			return nil, errors.New("egress: destination has unsupported scheme")
		}
		host := d.Host
		bracketed := false
		if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
			host, bracketed = host[1:len(host)-1], true
		}
		if strings.Contains(host, ":") {
			// Destination.Host is a separate field: bare IPv6 is accepted.
			// canonHost still rejects anything that is not a valid IPv6 literal.
			bracketed = true
		}
		canon, _, err := canonHost(host, bracketed)
		if err != nil {
			return nil, errors.New("egress: destination has invalid host")
		}
		port := d.Port
		if port == 0 {
			port = defaultPort(scheme)
			if port == 0 {
				return nil, errors.New("egress: destination requires explicit port")
			}
		}
		t := target{scheme: scheme, host: canon, port: port}
		if _, dup := allowed[t]; dup {
			return nil, errors.New("egress: duplicate destination")
		}
		if len(d.PrivateIPs) > maxPrivatePerEntry {
			return nil, errors.New("egress: too many private addresses")
		}
		// Public-only entries need no private set.
		var priv map[netip.Addr]struct{}
		if len(d.PrivateIPs) > 0 {
			priv = make(map[netip.Addr]struct{}, len(d.PrivateIPs))
		}
		for _, ip := range d.PrivateIPs {
			if !ip.IsValid() || ip.Zone() != "" {
				return nil, errors.New("egress: invalid private address")
			}
			ip = ip.Unmap()
			if classify(ip) != classPrivate {
				return nil, errors.New("egress: address is not an eligible private exception")
			}
			priv[ip] = struct{}{}
		}
		allowed[t] = priv
	}
	p := &Policy{
		limits:  limits,
		allowed: allowed,
		lookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			// Absolute name: never expand through resolver search domains.
			return resolver.LookupNetIP(ctx, "ip", host+".")
		},
		dialTCP: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	p.initHTTP()
	return p, nil
}

func validScheme(s string) bool {
	switch s {
	case "http", "https", "ws", "wss", "tcp", "tls":
		return true
	}
	return false
}

func defaultPort(scheme string) uint16 {
	switch scheme {
	case "http", "ws":
		return 80
	case "https", "wss":
		return 443
	}
	return 0
}

// authorize canonicalizes u and checks it is an exact allowed origin.
func (p *Policy) authorize(u *url.URL) (target, error) {
	var zero target
	if p == nil {
		return zero, ErrDenied
	}
	if u == nil || u.Opaque != "" || u.User != nil || u.Host == "" {
		return zero, errDeniedMalformed
	}
	scheme := strings.ToLower(u.Scheme)
	if !validScheme(scheme) {
		return zero, errDeniedMalformed
	}
	hostport := u.Host
	if strings.HasSuffix(hostport, ":") || strings.ContainsAny(hostport, "@ \t\r\n\\/?#") {
		return zero, errDeniedMalformed
	}
	bracketed := strings.HasPrefix(hostport, "[")
	host := u.Hostname()
	portStr := u.Port()
	canon, _, err := canonHost(host, bracketed)
	if err != nil {
		return zero, errDeniedMalformed
	}
	var port uint16
	if portStr == "" {
		port = defaultPort(scheme)
		if port == 0 {
			return zero, errDeniedMalformed
		}
	} else {
		n, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != portStr {
			return zero, errDeniedMalformed
		}
		port = uint16(n)
	}
	t := target{scheme: scheme, host: canon, port: port}
	if _, ok := p.allowed[t]; !ok {
		return zero, ErrDenied
	}
	return t, nil
}

// errDeniedMalformed is a static ErrDenied wrapper for unparsable origins.
var errDeniedMalformed error = deniedError{}

type deniedError struct{}

func (deniedError) Error() string        { return "egress: denied: malformed origin" }
func (deniedError) Is(target error) bool { return target == ErrDenied }

// canonHost returns the canonical host (lowercase ASCII DNS name without
// trailing dot, or canonical IP text) and the literal address when host is an
// IP literal. bracketed reports that host came from a bracketed IPv6 form.
func canonHost(host string, bracketed bool) (string, netip.Addr, error) {
	bad := errors.New("invalid host")
	if host == "" {
		return "", netip.Addr{}, bad
	}
	if bracketed || strings.Contains(host, ":") {
		if !bracketed || strings.ContainsAny(host, "%") {
			return "", netip.Addr{}, bad
		}
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is6() || a.Zone() != "" {
			return "", netip.Addr{}, bad
		}
		a = a.Unmap()
		return a.String(), a, nil
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if !a.Is4() || a.Zone() != "" {
			return "", netip.Addr{}, bad
		}
		return a.String(), a, nil
	}
	name := strings.TrimSuffix(host, ".")
	if name == "" || len(name) > maxHostLen {
		return "", netip.Addr{}, bad
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" || len(l) > maxLabelLen || l[0] == '-' || l[len(l)-1] == '-' {
			return "", netip.Addr{}, bad
		}
		for i := range len(l) {
			c := l[i]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", netip.Addr{}, bad
			}
		}
	}
	name = strings.ToLower(name)
	// A numeric-looking final label is an ambiguous IPv4 spelling
	// (127.1, 0x7f.1, 2130706433, 017700000001): refuse it.
	last := labels[len(labels)-1]
	if allDigits(last) || strings.HasPrefix(strings.ToLower(last), "0x") {
		return "", netip.Addr{}, bad
	}
	return name, netip.Addr{}, nil
}

func allDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// vetAddr requires a to be public or an explicitly allowed private exception.
// It unmaps a copy; the caller's answer is untouched.
func vetAddr(a netip.Addr, priv map[netip.Addr]struct{}) error {
	if !a.IsValid() || a.Zone() != "" {
		return ErrDenied
	}
	a = a.Unmap()
	switch classify(a) {
	case classPublic:
		return nil
	case classPrivate:
		if _, ok := priv[a]; ok {
			return nil
		}
	}
	return ErrDenied
}

// lookup resolves host. Context errors are reduced to the bare context
// sentinels; every other failure is ErrResolve with no raw cause.
func (p *Policy) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	got, err := p.lookupIP(ctx, host)
	if cerr := ctx.Err(); cerr != nil {
		return nil, cerr
	}
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return nil, context.Canceled
		case errors.Is(err, context.DeadlineExceeded):
			return nil, context.DeadlineExceeded
		}
		return nil, ErrResolve
	}
	if len(got) == 0 || len(got) > maxResolvedAnswers {
		return nil, ErrResolve
	}
	return got, nil
}

// dial resolves t, vets every answer, then connects to a vetted numeric
// address. Nothing is dialed unless all answers pass.
func (p *Policy) dial(ctx context.Context, t target) (net.Conn, error) {
	if p == nil {
		return nil, ErrDenied
	}
	priv, ok := p.allowed[t]
	if !ok {
		return nil, ErrDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var lit [1]netip.Addr
	var answers []netip.Addr
	if a, err := netip.ParseAddr(t.host); err == nil {
		lit[0] = a
		answers = lit[:]
	} else {
		answers, err = p.lookup(ctx, t.host)
		if err != nil {
			return nil, err
		}
	}
	for _, a := range answers {
		if err := vetAddr(a, priv); err != nil {
			return nil, err
		}
	}
	for _, a := range answers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := p.dialTCP(ctx, "tcp", netip.AddrPortFrom(a.Unmap(), t.port).String())
		if conn != nil {
			if cerr := ctx.Err(); cerr != nil {
				_ = conn.Close()
				return nil, cerr
			}
			if err == nil {
				return conn, nil
			}
			_ = conn.Close()
		}
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
	}
	return nil, ErrConnect
}

type class int

const (
	classDeny class = iota
	classPublic
	classPrivate
)

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

var (
	deniedRanges = prefixes(
		// IPv4 loopback, this-network, link-local (incl. cloud metadata),
		// multicast, reserved/broadcast, documentation, benchmarking,
		// protocol assignments, deprecated relay anycast.
		"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
		"192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
		"198.18.0.0/15", "192.88.99.0/24", "192.31.196.0/24", "192.52.193.0/24",
		"192.175.48.0/24",
		// Platform metadata outside link-local.
		"100.100.100.200/32", "168.63.129.16/32",
		// IPv6 unspecified, loopback, deprecated compat, NAT64, discard,
		// IETF/Teredo/ORCHID/benchmarking, documentation, 6to4, SRv6,
		// link-local, site-local, multicast, platform metadata.
		"::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
		"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16",
		"fe80::/10", "fec0::/10", "ff00::/8", "fd00:ec2::/32", "fd20:ce::254/128",
	)
	cgnat      = netip.MustParsePrefix("100.64.0.0/10")
	ula        = netip.MustParsePrefix("fc00::/7")
	globalUni6 = netip.MustParsePrefix("2000::/3")
)

// classify must be called with an unmapped address.
func classify(a netip.Addr) class {
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() {
		return classDeny
	}
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return classDeny
	}
	for _, p := range deniedRanges {
		if p.Contains(a) {
			return classDeny
		}
	}
	if a.Is4() {
		if a.IsPrivate() || cgnat.Contains(a) {
			return classPrivate
		}
		return classPublic
	}
	if ula.Contains(a) {
		return classPrivate
	}
	if globalUni6.Contains(a) {
		return classPublic
	}
	return classDeny
}
