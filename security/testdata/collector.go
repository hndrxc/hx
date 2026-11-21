// Fixture for Semgrep rule tests only; never built or executed. The rule path filter
// includes this file as a stand-in for internal/integrations and internal/collector.
package testdata

import (
	// ruleid: hx-go-direct-network-import
	"net"
	// ruleid: hx-go-direct-network-import
	"net/http"
	// ruleid: hx-go-direct-network-import
	stdhttp "net/http"
	// ruleid: hx-go-direct-network-import
	_ "net/http/httputil"
	// ruleid: hx-go-direct-network-import
	ws "github.com/gorilla/websocket"
	// ruleid: hx-go-direct-network-import
	"nhooyr.io/websocket"
	// ruleid: hx-go-direct-network-import
	. "golang.org/x/net/websocket"

	// ok: hx-go-direct-network-import
	"net/url"
	// ok: hx-go-direct-network-import
	"net/netip"
	// ok: hx-go-direct-network-import
	"github.com/hndrxc/hx/internal/egress"
)

// ruleid: hx-go-direct-network-import
import "net"

// ruleid: hx-go-direct-network-import
import alias "net/http"

var (
	_ = url.URL{}
	_ = netip.Addr{}
	_ = egress.Policy{}
)
