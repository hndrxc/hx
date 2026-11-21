package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestSecurityFoundationRebinding drives the public Dial pipeline through the
// lookup and dial seams only. The first resolution is fully vetted and the
// dial receives an exact numeric address, never the hostname. A later lookup
// contaminated by one forbidden answer is refused before any dial, with a
// sanitized error. All fixtures are synthetic; nothing leaves the process.
func TestSecurityFoundationRebinding(t *testing.T) {
	const host = "svc.example.com"
	cases := []struct {
		name   string
		second []netip.Addr
	}{
		{"ipv4-loopback", addrs("93.184.216.34", "127.0.0.1")},
		{"ipv4-metadata", addrs("169.254.169.254", "93.184.216.34")},
		{"ipv6-metadata", addrs("2606:4700::1111", "fd00:ec2::254")},
		{"ipv6-loopback", addrs("::1")},
		{"mapped-private", addrs("::ffff:10.0.0.1")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			f := &fakeNet{answers: [][]netip.Addr{addrs("93.184.216.34", "2606:4700::1111"), tc.second}}
			p := newTest(t, []Destination{{Scheme: "tcp", Host: host, Port: 9000}}, f)
			var hosts []string
			p.lookupIP = func(ctx context.Context, h string) ([]netip.Addr, error) {
				hosts = append(hosts, h)
				return f.lookup(ctx, h)
			}
			p.dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
				f.mu.Lock()
				f.dialed = append(f.dialed, addr)
				f.mu.Unlock()
				c, s := net.Pipe()
				t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
				return c, nil
			}
			u := &url.URL{Scheme: "tcp", Host: host + ":9000"}

			conn, err := p.Dial(ctx, u)
			if err != nil {
				t.Fatalf("first dial: %v", err)
			}
			_ = conn.Close()
			if len(f.dialed) != 1 || f.dialed[0] != "93.184.216.34:9000" {
				t.Fatalf("first dial targets = %v, want exact vetted numeric address", f.dialed)
			}
			if ap, perr := netip.ParseAddrPort(f.dialed[0]); perr != nil || !ap.Addr().IsValid() {
				t.Fatal("dial seam received a non-numeric address")
			}

			_, err = p.Dial(ctx, u)
			if !errors.Is(err, ErrDenied) {
				t.Fatalf("contaminated lookup: got %v, want ErrDenied", err)
			}
			if err != nil {
				msg := err.Error()
				for _, a := range tc.second {
					if strings.Contains(msg, a.String()) || strings.Contains(msg, a.Unmap().String()) {
						t.Fatal("error message leaks a resolved address")
					}
				}
				if strings.Contains(msg, host) {
					t.Fatal("error message leaks the hostname")
				}
			}
			if f.lookups != 2 || len(f.dialed) != 1 {
				t.Fatalf("lookups=%d dials=%d, want 2 lookups and no dial after contamination", f.lookups, len(f.dialed))
			}
			for _, h := range hosts {
				if h != host {
					t.Fatalf("lookup host = %q, want canonical %q", h, host)
				}
			}
		})
	}
}
