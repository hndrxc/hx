package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

var testLimits = Limits{Timeout: time.Second, MaxBodyBytes: 1 << 10}

type fakeNet struct {
	mu       sync.Mutex
	answers  [][]netip.Addr // consumed one per lookup; last repeats
	lookups  int
	dialed   []string
	failDial map[string]bool
	lookErr  error
}

func (f *fakeNet) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	if f.lookErr != nil {
		return nil, f.lookErr
	}
	i := f.lookups - 1
	if i >= len(f.answers) {
		i = len(f.answers) - 1
	}
	return f.answers[i], nil
}

func (f *fakeNet) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dialed = append(f.dialed, addr)
	if f.failDial[addr] {
		return nil, errors.New("refused " + addr)
	}
	c, s := net.Pipe()
	_ = s.Close()
	return c, nil
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func newTest(t *testing.T, dests []Destination, f *fakeNet) *Policy {
	t.Helper()
	p, err := New(dests, testLimits)
	if err != nil {
		t.Fatal(err)
	}
	p.lookupIP = f.lookup
	p.dialTCP = f.dial
	return p
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestNewValidation(t *testing.T) {
	ok := Destination{Scheme: "https", Host: "example.com"}
	cases := map[string]struct {
		d []Destination
		l Limits
	}{
		"no destinations":   {nil, testLimits},
		"zero timeout":      {[]Destination{ok}, Limits{MaxBodyBytes: 1}},
		"zero body":         {[]Destination{ok}, Limits{Timeout: time.Second}},
		"bad scheme":        {[]Destination{{Scheme: "ftp", Host: "example.com"}}, testLimits},
		"upper scheme":      {[]Destination{{Scheme: "HTTPS", Host: "example.com"}}, testLimits},
		"tcp needs port":    {[]Destination{{Scheme: "tcp", Host: "example.com"}}, testLimits},
		"tls needs port":    {[]Destination{{Scheme: "tls", Host: "example.com"}}, testLimits},
		"wildcard":          {[]Destination{{Scheme: "https", Host: "*.example.com"}}, testLimits},
		"underscore":        {[]Destination{{Scheme: "https", Host: "a_b.example.com"}}, testLimits},
		"unicode":           {[]Destination{{Scheme: "https", Host: "bücher.example"}}, testLimits},
		"empty label":       {[]Destination{{Scheme: "https", Host: "a..example.com"}}, testLimits},
		"hyphen edge":       {[]Destination{{Scheme: "https", Host: "-a.example.com"}}, testLimits},
		"short ipv4":        {[]Destination{{Scheme: "https", Host: "127.1"}}, testLimits},
		"hex ipv4":          {[]Destination{{Scheme: "https", Host: "0x7f.0.0.1"}}, testLimits},
		"decimal ipv4":      {[]Destination{{Scheme: "https", Host: "2130706433"}}, testLimits},
		"leading zero ipv4": {[]Destination{{Scheme: "https", Host: "010.0.0.1"}}, testLimits},
		"zone ipv6":         {[]Destination{{Scheme: "https", Host: "[fe80::1%eth0]"}}, testLimits},
		"bare ipv6 zone":    {[]Destination{{Scheme: "https", Host: "fe80::1%eth0"}}, testLimits},
		"host with port":    {[]Destination{{Scheme: "https", Host: "example.com:443"}}, testLimits},
		"double brackets":   {[]Destination{{Scheme: "https", Host: "[[2606:4700::1]]"}}, testLimits},
		"private metadata ula gcp": {[]Destination{{Scheme: "https", Host: "example.com",
			PrivateIPs: addrs("fd20:ce::254")}}, testLimits},
		"duplicate": {[]Destination{ok, ok}, testLimits},
		"long name": {[]Destination{{Scheme: "https", Host: strings.Repeat("a", 64) + ".example"}}, testLimits},
		"private loopback": {[]Destination{{Scheme: "https", Host: "example.com",
			PrivateIPs: addrs("127.0.0.1")}}, testLimits},
		"private public": {[]Destination{{Scheme: "https", Host: "example.com",
			PrivateIPs: addrs("8.8.8.8")}}, testLimits},
		"private metadata v4": {[]Destination{{Scheme: "https", Host: "example.com",
			PrivateIPs: addrs("169.254.169.254")}}, testLimits},
		"private metadata ula": {[]Destination{{Scheme: "https", Host: "example.com",
			PrivateIPs: addrs("fd00:ec2::254")}}, testLimits},
		"private alibaba": {[]Destination{{Scheme: "https", Host: "example.com",
			PrivateIPs: addrs("100.100.100.200")}}, testLimits},
		"private invalid": {[]Destination{{Scheme: "https", Host: "example.com",
			PrivateIPs: []netip.Addr{{}}}}, testLimits},
		"private linklocal v6": {[]Destination{{Scheme: "https", Host: "example.com",
			PrivateIPs: addrs("fe80::1")}}, testLimits},
		"private nat64": {[]Destination{{Scheme: "https", Host: "example.com",
			PrivateIPs: addrs("64:ff9b::a00:1")}}, testLimits},
		"private mapped loopback": {[]Destination{{Scheme: "https", Host: "example.com",
			PrivateIPs: addrs("::ffff:127.0.0.1")}}, testLimits},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(c.d, c.l); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	good := []Destination{
		{Scheme: "https", Host: "Example.COM."},
		{Scheme: "tcp", Host: "db.internal", Port: 5432, PrivateIPs: addrs("10.0.0.5", "100.64.1.1", "fd12::5", "::ffff:192.168.1.1")},
		{Scheme: "wss", Host: "[2606:4700::1]"},
		{Scheme: "tls", Host: "2606:4700::2", Port: 853},
	}
	if _, err := New(good, testLimits); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorize(t *testing.T) {
	p := newTest(t, []Destination{
		{Scheme: "https", Host: "example.com"},
		{Scheme: "http", Host: "example.com", Port: 8080},
		{Scheme: "wss", Host: "ws.example.com"},
		{Scheme: "tcp", Host: "db.example.com", Port: 5432},
		{Scheme: "https", Host: "[2606:4700::1111]"},
		{Scheme: "https", Host: "93.184.216.34"},
	}, &fakeNet{})
	allowed := map[string]target{
		"https://example.com/x":             {"https", "example.com", 443},
		"HTTPS://EXAMPLE.com:443/":          {"https", "example.com", 443},
		"https://example.com./":             {"https", "example.com", 443},
		"http://example.com:8080":           {"http", "example.com", 8080},
		"wss://ws.example.com/sock":         {"wss", "ws.example.com", 443},
		"tcp://db.example.com:5432":         {"tcp", "db.example.com", 5432},
		"https://[2606:4700::1111]/":        {"https", "2606:4700::1111", 443},
		"https://[2606:4700:0:0::1111]:443": {"https", "2606:4700::1111", 443},
		"https://93.184.216.34/":            {"https", "93.184.216.34", 443},
		"https://[::ffff:93.184.216.34]/":   {"https", "93.184.216.34", 443},
	}
	for s, want := range allowed {
		got, err := p.authorize(mustURL(t, s))
		if err != nil || got != want {
			t.Errorf("%s: got %v %v, want %v", s, got, err, want)
		}
	}
	denied := []string{
		"https://example.com:444/",
		"http://example.com/", // port 80 not allowed
		"https://other.example.com/",
		"https://sub.example.com/",
		"https://example.com:/", // empty port
		"https://user@example.com/",
		"https://user:pw@example.com/",
		"https:example.com", // opaque
		"https:///path",
		"https://example.com:0443/",
		"https://example.com:00/",
		"https://example.com:+443/",
		"tcp://db.example.com/", // tcp needs port
		"tcp://db.example.com:5433",
		"ftp://example.com/",
		"https://[fe80::1%25eth0]/",
		"https://0x5d.184.216.34/",
		"https://93.184.216.034/",
		"https://1534320674/",
		"https://example.com%2e/",
		"https://exam_ple.com/",
	}
	for _, s := range denied {
		u, err := url.Parse(s)
		if err != nil {
			continue // rejected by the URL parser itself
		}
		if _, err := p.authorize(u); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: err = %v, want ErrDenied", s, err)
		}
	}
	if _, err := p.authorize(nil); !errors.Is(err, ErrDenied) {
		t.Error("nil URL not denied")
	}
}

func TestMappedLiteralNormalizes(t *testing.T) {
	p := newTest(t, []Destination{{Scheme: "https", Host: "[::ffff:93.184.216.34]"}}, &fakeNet{})
	// Mapped form is canonicalized to the dotted IPv4 text; bracketed v6 text
	// normalizes to the same unmapped address.
	if _, ok := p.allowed[target{"https", "93.184.216.34", 443}]; !ok {
		t.Fatalf("mapped literal not normalized: %v", p.allowed)
	}
}

func TestClassify(t *testing.T) {
	public := []string{"8.8.8.8", "93.184.216.34", "1.1.1.1", "2606:4700::1111", "2001:4860:4860::8888"}
	private := []string{"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.1", "100.64.0.1", "100.127.255.254", "fc00::1", "fd12:3456::1"}
	deny := []string{
		"127.0.0.1", "127.255.255.254", "0.0.0.0", "0.1.2.3", "169.254.169.254", "169.254.0.1",
		"224.0.0.1", "239.255.255.250", "255.255.255.255", "240.0.0.1", "192.0.0.192", "192.0.2.1",
		"198.51.100.1", "203.0.113.1", "198.18.0.1", "192.88.99.1", "100.100.100.200", "168.63.129.16",
		"::", "::1", "fe80::1", "fec0::1", "ff02::1", "ff01::1", "fd00:ec2::254", "fd20:ce::254", "64:ff9b::808:808",
		"64:ff9b:1::1", "100::1", "2001::1", "2001:db8::1", "2002:808:808::1", "2001:2::1", "5f00::1",
		"3fff::1", "::8.8.8.8", "4000::1", "1::1",
	}
	for _, s := range public {
		if c := classify(netip.MustParseAddr(s)); c != classPublic {
			t.Errorf("%s: class %d, want public", s, c)
		}
	}
	for _, s := range private {
		if c := classify(netip.MustParseAddr(s)); c != classPrivate {
			t.Errorf("%s: class %d, want private", s, c)
		}
	}
	for _, s := range deny {
		if c := classify(netip.MustParseAddr(s)); c != classDeny {
			t.Errorf("%s: class %d, want deny", s, c)
		}
	}
	if classify(netip.MustParseAddr("::ffff:8.8.8.8")) != classDeny {
		t.Error("unnormalized mapped address must not classify")
	}
	if classify(netip.MustParseAddr("fe80::1%eth0")) != classDeny {
		t.Error("zoned address must be denied")
	}
}

func tgt(p *Policy, t *testing.T, s string) target {
	t.Helper()
	tg, err := p.authorize(mustURL(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestDialPublic(t *testing.T) {
	f := &fakeNet{answers: [][]netip.Addr{addrs("93.184.216.34", "2606:4700::1111")}}
	p := newTest(t, []Destination{{Scheme: "tcp", Host: "svc.example.com", Port: 9000}}, f)
	c, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:9000"))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(f.dialed) != 1 || f.dialed[0] != "93.184.216.34:9000" {
		t.Fatalf("dialed %v", f.dialed)
	}
}

func TestDialFallsBackAcrossAddresses(t *testing.T) {
	f := &fakeNet{
		answers:  [][]netip.Addr{addrs("2606:4700::1111", "93.184.216.34")},
		failDial: map[string]bool{"[2606:4700::1111]:9000": true},
	}
	p := newTest(t, []Destination{{Scheme: "tcp", Host: "svc.example.com", Port: 9000}}, f)
	c, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:9000"))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(f.dialed) != 2 || f.dialed[1] != "93.184.216.34:9000" {
		t.Fatalf("dialed %v", f.dialed)
	}
}

func TestDialAllFail(t *testing.T) {
	f := &fakeNet{
		answers:  [][]netip.Addr{addrs("93.184.216.34")},
		failDial: map[string]bool{"93.184.216.34:9000": true},
	}
	p := newTest(t, []Destination{{Scheme: "tcp", Host: "svc.example.com", Port: 9000}}, f)
	_, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:9000"))
	if !errors.Is(err, ErrConnect) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "93.184") || strings.Contains(err.Error(), "refused") {
		t.Fatalf("error leaks detail: %v", err)
	}
}

func TestMixedAnswersDenyBeforeAnyDial(t *testing.T) {
	bad := []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "100.64.0.1", "::1", "fd00:ec2::254",
		"0.0.0.0", "224.0.0.1", "64:ff9b::808:808", "192.0.0.192", "fe80::1", "fd12::1"}
	for _, b := range bad {
		for _, order := range [][]string{{"93.184.216.34", b}, {b, "93.184.216.34"}} {
			f := &fakeNet{answers: [][]netip.Addr{addrs(order...)}}
			p := newTest(t, []Destination{{Scheme: "tcp", Host: "svc.example.com", Port: 9000}}, f)
			_, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:9000"))
			if !errors.Is(err, ErrDenied) {
				t.Errorf("%v: err = %v", order, err)
			}
			if len(f.dialed) != 0 {
				t.Errorf("%v: dialed %v before vetting complete", order, f.dialed)
			}
			if err != nil && strings.Contains(err.Error(), b) {
				t.Errorf("error leaks address: %v", err)
			}
		}
	}
}

func TestPrivateExactAllowance(t *testing.T) {
	f := &fakeNet{answers: [][]netip.Addr{addrs("10.0.0.5")}}
	p := newTest(t, []Destination{{Scheme: "tcp", Host: "db.example.com", Port: 5432, PrivateIPs: addrs("10.0.0.5")}}, f)
	c, err := p.dial(context.Background(), tgt(p, t, "tcp://db.example.com:5432"))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	// A neighbouring address, even in the same subnet, is denied.
	f2 := &fakeNet{answers: [][]netip.Addr{addrs("10.0.0.6")}}
	p.lookupIP, p.dialTCP = f2.lookup, f2.dial
	if _, err := p.dial(context.Background(), tgt(p, t, "tcp://db.example.com:5432")); !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v", err)
	}
	if len(f2.dialed) != 0 {
		t.Fatal("dialed denied address")
	}

	// Allowance is per destination, not global.
	p2 := newTest(t, []Destination{
		{Scheme: "tcp", Host: "db.example.com", Port: 5432, PrivateIPs: addrs("10.0.0.5")},
		{Scheme: "tcp", Host: "other.example.com", Port: 5432},
	}, &fakeNet{answers: [][]netip.Addr{addrs("10.0.0.5")}})
	if _, err := p2.dial(context.Background(), tgt(p2, t, "tcp://other.example.com:5432")); !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestMappedAnswerNormalized(t *testing.T) {
	f := &fakeNet{answers: [][]netip.Addr{addrs("::ffff:127.0.0.1")}}
	p := newTest(t, []Destination{{Scheme: "tcp", Host: "svc.example.com", Port: 9000}}, f)
	if _, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:9000")); !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v", err)
	}
	f = &fakeNet{answers: [][]netip.Addr{addrs("::ffff:93.184.216.34")}}
	p.lookupIP, p.dialTCP = f.lookup, f.dial
	c, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:9000"))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if f.dialed[0] != "93.184.216.34:9000" {
		t.Fatalf("dialed %v", f.dialed)
	}
}

func TestAnswersChangeBetweenCalls(t *testing.T) {
	f := &fakeNet{answers: [][]netip.Addr{addrs("93.184.216.34"), addrs("169.254.169.254")}}
	p := newTest(t, []Destination{{Scheme: "tcp", Host: "svc.example.com", Port: 9000}}, f)
	tg := tgt(p, t, "tcp://svc.example.com:9000")
	c, err := p.dial(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if _, err := p.dial(context.Background(), tg); !errors.Is(err, ErrDenied) {
		t.Fatalf("second dial err = %v", err)
	}
	if f.lookups != 2 || len(f.dialed) != 1 {
		t.Fatalf("lookups=%d dialed=%v", f.lookups, f.dialed)
	}
}

func TestLiteralHost(t *testing.T) {
	f := &fakeNet{}
	p := newTest(t, []Destination{
		{Scheme: "tcp", Host: "93.184.216.34", Port: 1},
		{Scheme: "tcp", Host: "127.0.0.1", Port: 1},
		{Scheme: "tcp", Host: "10.0.0.5", Port: 1, PrivateIPs: addrs("10.0.0.5")},
		{Scheme: "tcp", Host: "10.0.0.6", Port: 1},
		{Scheme: "tcp", Host: "[::ffff:127.0.0.1]", Port: 2},
	}, f)
	if f.lookups != 0 {
		t.Fatal("unexpected lookup")
	}
	for u, want := range map[string]error{
		"tcp://93.184.216.34:1":      nil,
		"tcp://127.0.0.1:1":          ErrDenied,
		"tcp://10.0.0.5:1":           nil,
		"tcp://10.0.0.6:1":           ErrDenied,
		"tcp://[::ffff:127.0.0.1]:2": ErrDenied,
		"tcp://[::ffff:7f00:1]:2":    ErrDenied,
	} {
		c, err := p.dial(context.Background(), tgt(p, t, u))
		if c != nil {
			_ = c.Close()
		}
		if !errors.Is(err, want) || (want == nil && err != nil) {
			t.Errorf("%s: err = %v, want %v", u, err, want)
		}
	}
	if f.lookups != 0 {
		t.Fatal("literal hosts must not use DNS")
	}
}

func TestResolveFailures(t *testing.T) {
	dest := []Destination{{Scheme: "tcp", Host: "svc.example.com", Port: 9000}}
	// Raw cause must not leak.
	f := &fakeNet{lookErr: errors.New("secret.internal NXDOMAIN 10.9.9.9")}
	p := newTest(t, dest, f)
	_, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:9000"))
	if !errors.Is(err, ErrResolve) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "10.9") {
		t.Fatalf("err = %v", err)
	}
	// Empty answer.
	f = &fakeNet{answers: [][]netip.Addr{{}}}
	p = newTest(t, dest, f)
	if _, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:9000")); !errors.Is(err, ErrResolve) {
		t.Fatalf("empty: err = %v", err)
	}
	// Excess answers fail closed even if all are public.
	many := make([]netip.Addr, maxResolvedAnswers+1)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{93, 184, 216, byte(i + 1)})
	}
	f = &fakeNet{answers: [][]netip.Addr{many}}
	p = newTest(t, dest, f)
	if _, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:9000")); !errors.Is(err, ErrResolve) {
		t.Fatalf("excess: err = %v", err)
	}
	if len(f.dialed) != 0 {
		t.Fatal("dialed after excess answers")
	}
	// Exactly the cap is fine.
	f = &fakeNet{answers: [][]netip.Addr{many[:maxResolvedAnswers]}}
	p = newTest(t, dest, f)
	c, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:9000"))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

func TestInvalidAnswerAddress(t *testing.T) {
	f := &fakeNet{answers: [][]netip.Addr{{{}}}}
	p := newTest(t, []Destination{{Scheme: "tcp", Host: "svc.example.com", Port: 9000}}, f)
	if _, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:9000")); !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestLookupReceivesNormalizedName(t *testing.T) {
	var got string
	f := &fakeNet{answers: [][]netip.Addr{addrs("93.184.216.34")}}
	p := newTest(t, []Destination{{Scheme: "tcp", Host: "Svc.Example.COM.", Port: 9000}}, f)
	p.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		got = host
		return f.lookup(ctx, host)
	}
	c, err := p.dial(context.Background(), tgt(p, t, "tcp://SVC.example.com.:9000"))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if got != "svc.example.com" {
		t.Fatalf("lookup host %q", got)
	}
}

func TestPolicyDialCancellation(t *testing.T) {
	dest := []Destination{{Scheme: "tcp", Host: "svc.example.com", Port: 9000}}

	// Canceled before start: no lookup, no dial.
	f := &fakeNet{answers: [][]netip.Addr{addrs("93.184.216.34")}}
	p := newTest(t, dest, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.dial(ctx, tgt(p, t, "tcp://svc.example.com:9000")); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if f.lookups != 0 || len(f.dialed) != 0 {
		t.Fatal("work done after cancel")
	}

	// Lookup returns a wrapped context error: preserved.
	f = &fakeNet{lookErr: context.DeadlineExceeded}
	p = newTest(t, dest, f)
	if _, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:9000")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}

	// Cancel during lookup: context error wins over any answer.
	ctx, cancel = context.WithCancel(context.Background())
	f = &fakeNet{answers: [][]netip.Addr{addrs("93.184.216.34")}}
	p = newTest(t, dest, f)
	p.lookupIP = func(c context.Context, h string) ([]netip.Addr, error) {
		cancel()
		return f.lookup(c, h)
	}
	if _, err := p.dial(ctx, tgt(p, t, "tcp://svc.example.com:9000")); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if len(f.dialed) != 0 {
		t.Fatal("dialed after cancel")
	}

	// Cancel during dial: not reported as ErrConnect, no further attempts.
	ctx, cancel = context.WithCancel(context.Background())
	f = &fakeNet{answers: [][]netip.Addr{addrs("93.184.216.34", "93.184.216.35")}}
	p = newTest(t, dest, f)
	p.dialTCP = func(c context.Context, n, a string) (net.Conn, error) {
		f.dialed = append(f.dialed, a)
		cancel()
		return nil, c.Err()
	}
	_, err := p.dial(ctx, tgt(p, t, "tcp://svc.example.com:9000"))
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrConnect) {
		t.Fatalf("err = %v", err)
	}
	if len(f.dialed) != 1 {
		t.Fatalf("dialed %v", f.dialed)
	}
}

func TestDialUnauthorizedTarget(t *testing.T) {
	f := &fakeNet{answers: [][]netip.Addr{addrs("93.184.216.34")}}
	p := newTest(t, []Destination{{Scheme: "tcp", Host: "svc.example.com", Port: 9000}}, f)
	_, err := p.dial(context.Background(), target{"tcp", "evil.example.com", 9000})
	if !errors.Is(err, ErrDenied) || f.lookups != 0 {
		t.Fatalf("err = %v lookups = %d", err, f.lookups)
	}
}

func TestBareIPv6Destination(t *testing.T) {
	f := &fakeNet{}
	p := newTest(t, []Destination{{Scheme: "tls", Host: "2606:4700::2", Port: 853}}, f)
	if _, ok := p.allowed[target{"tls", "2606:4700::2", 853}]; !ok {
		t.Fatalf("bare IPv6 not normalized: %v", p.allowed)
	}
	// URL authority still requires brackets.
	if _, err := p.authorize(&url.URL{Scheme: "tls", Host: "2606:4700::2:853"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("unbracketed authority: %v", err)
	}
	tg := tgt(p, t, "tls://[2606:4700::2]:853")
	c, err := p.dial(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if f.lookups != 0 || len(f.dialed) != 1 || f.dialed[0] != "[2606:4700::2]:853" {
		t.Fatalf("lookups %d dialed %v", f.lookups, f.dialed)
	}
}

func TestGCPMetadataULAHardDenied(t *testing.T) {
	f := &fakeNet{answers: [][]netip.Addr{addrs("fd20:ce::254")}}
	p := newTest(t, []Destination{
		{Scheme: "tcp", Host: "svc.example.com", Port: 1},
		{Scheme: "tcp", Host: "fd20:ce::254", Port: 2},
	}, f)
	if _, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:1")); !errors.Is(err, ErrDenied) {
		t.Fatalf("lookup answer: %v", err)
	}
	if _, err := p.dial(context.Background(), tgt(p, t, "tcp://[fd20:ce::254]:2")); !errors.Is(err, ErrDenied) {
		t.Fatalf("literal: %v", err)
	}
	if len(f.dialed) != 0 {
		t.Fatalf("dialed %v", f.dialed)
	}
}

func TestNilPolicy(t *testing.T) {
	var p *Policy
	if _, err := p.authorize(mustURL(t, "tcp://svc.example.com:1")); !errors.Is(err, ErrDenied) {
		t.Fatalf("authorize: %v", err)
	}
	if _, err := p.dial(context.Background(), target{"tcp", "svc.example.com", 1}); !errors.Is(err, ErrDenied) {
		t.Fatalf("dial: %v", err)
	}
	if _, err := p.Dial(context.Background(), mustURL(t, "tcp://svc.example.com:1")); !errors.Is(err, ErrDenied) {
		t.Fatalf("Dial: %v", err)
	}
}

func TestWrappedContextErrorCanonical(t *testing.T) {
	dest := []Destination{{Scheme: "tcp", Host: "svc.example.com", Port: 9000}}
	for _, want := range []error{context.Canceled, context.DeadlineExceeded} {
		f := &fakeNet{lookErr: fmt.Errorf("lookup secret.internal 10.9.9.9: %w", want)}
		p := newTest(t, dest, f)
		_, err := p.dial(context.Background(), tgt(p, t, "tcp://svc.example.com:9000"))
		if err != want {
			t.Fatalf("err = %#v, want bare %v", err, want)
		}
	}
}

func TestConnClosedWhenCanceledAfterDial(t *testing.T) {
	dest := []Destination{{Scheme: "tcp", Host: "svc.example.com", Port: 9000}}
	f := &fakeNet{answers: [][]netip.Addr{addrs("93.184.216.34")}}
	p := newTest(t, dest, f)
	ctx, cancel := context.WithCancel(context.Background())
	local, remote := net.Pipe()
	defer remote.Close()
	p.dialTCP = func(context.Context, string, string) (net.Conn, error) {
		cancel()
		return local, nil
	}
	c, err := p.dial(ctx, tgt(p, t, "tcp://svc.example.com:9000"))
	if c != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("conn %v err %v", c, err)
	}
	if _, err := local.Write([]byte("x")); err == nil {
		t.Fatal("connection received after cancellation was not closed")
	}
}

func TestPublicOnlyEntryHasNoPrivateSet(t *testing.T) {
	p := newTest(t, []Destination{{Scheme: "https", Host: "example.com"}}, &fakeNet{})
	if priv := p.allowed[target{"https", "example.com", 443}]; priv != nil {
		t.Fatalf("unexpected private set %v", priv)
	}
}
