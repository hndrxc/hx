//go:build windows

package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/hndrxc/hx/internal/hub/audit"
)

func testPipeName(t *testing.T) string {
	return fmt.Sprintf("hx-ipc-test-%d-%d", os.Getpid(), time.Now().UnixNano())
}

func selfSID(t *testing.T) *windows.SID {
	t.Helper()
	sid, err := processUserSID()
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func otherSID(t *testing.T, self *windows.SID) *windows.SID {
	t.Helper()
	for _, k := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinLocalServiceSid} {
		s, err := windows.CreateWellKnownSid(k)
		if err != nil {
			t.Fatal(err)
		}
		if !windows.EqualSid(s, self) {
			return s
		}
	}
	t.Fatal("no unrelated SID available")
	return nil
}

// rawDial connects without sending the transport preface.
func rawDial(t *testing.T, name string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return winio.DialPipeContext(ctx, localPipePrefix+name)
}

// dial connects and writes the one-byte transport preface the server must
// read before ImpersonateNamedPipeClient has a client message context.
func dial(t *testing.T, name string) (net.Conn, error) {
	c, err := rawDial(t, name)
	if err != nil {
		return nil, err
	}
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{pipePreface}); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetWriteDeadline(time.Time{})
	return c, nil
}

func TestListenPipeIntendedSIDRoundTrip(t *testing.T) {
	name := testPipeName(t)
	sid := selfSID(t)
	log := &recLog{}
	l, err := ListenPipe(name, sid, audit.NewHooks(log))
	if err != nil {
		t.Fatal(err)
	}
	if n := l.raw.Addr().Network(); n != "pipe" {
		t.Fatalf("listener network %q, want pipe (no TCP fallback)", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Serve(ctx, echo) }()
	defer func() {
		cancel()
		<-done
	}()
	c, err := dial(t, name)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	writeAsync(c, frame([]byte("ping")))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := readFrame(c)
	if err != nil || string(got) != "ping" {
		t.Fatalf("got %q, %v", got, err)
	}
	ev := log.snapshot()
	if len(ev) != 1 || ev[0].Outcome != audit.OutcomeAllowed || ev[0].ActorID != sidActor(sid) {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestPipeDACLExclusiveAndProtected(t *testing.T) {
	name := testPipeName(t)
	sid := selfSID(t)
	l, err := ListenPipe(name, sid, audit.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// Query the DACL through an open handle to the pipe instance rather
	// than a named-object lookup. The client handle's GENERIC_READ includes
	// READ_CONTROL.
	c, err := rawDial(t, name)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fc, ok := c.(fdConn)
	if !ok {
		t.Fatal("pipe client exposes no handle")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(fc.Fd()), windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ctl, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if ctl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("DACL not protected")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL missing: %v", err)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("DACL has %d ACEs, want 1", dacl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !windows.EqualSid(aceSID, sid) {
		t.Fatalf("unexpected ACE for %v", aceSID)
	}
	if got := pipeSDDL(sid); got != "O:"+sid.String()+"D:P(A;;GA;;;"+sid.String()+")" {
		t.Fatalf("sddl %q", got)
	}
}

func TestListenPipeRejectsUnrelatedSID(t *testing.T) {
	other := otherSID(t, selfSID(t))
	if _, err := ListenPipe(testPipeName(t), other, audit.Hooks{}); err == nil {
		t.Fatal("ListenPipe accepted a SID that is not the service account")
	}
}

func TestAuthorizeRejectsUnrelatedClientSID(t *testing.T) {
	name := testPipeName(t)
	self := selfSID(t)
	raw, err := winio.ListenPipe(localPipePrefix+name, &winio.PipeConfig{SecurityDescriptor: pipeSDDL(self)})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	other := otherSID(t, self)
	res := make(chan error, 1)
	go func() {
		c, err := raw.Accept()
		if err != nil {
			res <- err
			return
		}
		defer c.Close()
		_, err = authorizePipe(c, other)
		res <- err
	}()
	c, err := dial(t, name)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := <-res; !errors.Is(err, errClientSIDNotAuthorized) {
		t.Fatalf("peer check = %v, want client SID not authorized", err)
	}
}

func TestAuthorizeStableActor(t *testing.T) {
	s := selfSID(t)
	if sidActor(s) != sidActor(s) || sidActor(s).IsZero() {
		t.Fatal("actor not stable")
	}
	if sidActor(s) == sidActor(otherSID(t, s)) {
		t.Fatal("actor collision")
	}
}

func TestListenPipeRejectsBadInput(t *testing.T) {
	sid := selfSID(t)
	for _, n := range []string{"", `..\x`, `a\b`, "a/b", `\\host\pipe\x`, "server\\x", "-lead", string(make([]byte, 200))} {
		if _, err := ListenPipe(n, sid, audit.Hooks{}); err == nil {
			t.Fatalf("accepted name %q", n)
		}
	}
	if _, err := ListenPipe(testPipeName(t), nil, audit.Hooks{}); err == nil {
		t.Fatal("accepted nil SID")
	}
	if _, err := ListenPipe(testPipeName(t), &windows.SID{}, audit.Hooks{}); err == nil {
		t.Fatal("accepted invalid SID")
	}
}

func TestListenPipeRefusesExistingPipe(t *testing.T) {
	name := testPipeName(t)
	sid := selfSID(t)
	l, err := ListenPipe(name, sid, audit.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l2, err := ListenPipe(name, sid, audit.Hooks{}); err == nil {
		l2.Close()
		t.Fatal("second listener on existing pipe succeeded")
	}
}

func TestDialRemoteNamespaceRefused(t *testing.T) {
	// Pipe names cannot carry a host; remote access is rejected by
	// FILE_PIPE_REJECT_REMOTE_CLIENTS which go-winio sets unconditionally.
	if pipeNamePattern.MatchString(`\\remote\pipe\x`) {
		t.Fatal("remote path accepted as name")
	}
}
