//go:build windows

package ipc

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"runtime"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/hndrxc/hx/internal/hub/audit"
)

// pipeNamePattern restricts pipe names to a single component under the local
// \\.\pipe\ namespace: no separators, no host component, no device tricks.
var pipeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// localPipePrefix is the only namespace used: "." is the local machine.
const localPipePrefix = `\\.\pipe\`

// ListenPipe creates the local administration named pipe \\.\pipe\<name>.
//
// Security properties:
//   - The pipe lives only in the local namespace; go-winio v0.6.4 always
//     creates the server end with FILE_PIPE_REJECT_REMOTE_CLIENTS, so SMB
//     clients are rejected by the kernel. The first instance is created with
//     FILE_CREATE, so an existing (possibly squatted) pipe makes this fail.
//   - The DACL is protected (no inheritance) and grants GENERIC_ALL to sid
//     only; owner is sid. There is no default/public fallback.
//   - sid must equal the primary token user of this process: the service and
//     intended client run as the same account. This avoids needing
//     cross-account permission separation and makes the DACL exclusive.
//   - Every accepted connection is re-authenticated by impersonating the
//     client and comparing the impersonation token user SID with sid.
//     ImpersonateNamedPipeClient uses the security context of the last
//     message read, so the client must first send the single transport
//     preface byte pipePreface; it is consumed before token inspection and
//     is not part of any application frame. PIDs are never consulted.
func ListenPipe(name string, sid *windows.SID, hooks audit.Hooks) (*Listener, error) {
	if !pipeNamePattern.MatchString(name) {
		return nil, fmt.Errorf("ipc: invalid pipe name %q", name)
	}
	if sid == nil || !sid.IsValid() {
		return nil, errors.New("ipc: invalid SID")
	}
	self, err := processUserSID()
	if err != nil {
		return nil, fmt.Errorf("ipc: process token: %w", err)
	}
	if !windows.EqualSid(self, sid) {
		return nil, errors.New("ipc: intended SID differs from service account SID")
	}
	sddl := pipeSDDL(sid)
	// Validate the descriptor locally so malformed input fails closed before
	// any kernel object is created.
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("ipc: security descriptor: %w", err)
	}
	if !sd.IsValid() {
		return nil, errors.New("ipc: invalid security descriptor")
	}
	raw, err := winio.ListenPipe(localPipePrefix+name, &winio.PipeConfig{SecurityDescriptor: sddl})
	if err != nil {
		return nil, fmt.Errorf("ipc: listen pipe: %w", err)
	}
	want, err := sid.Copy()
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return newListener(raw, func(c net.Conn) (audit.ID, error) { return authorizePipe(c, want) }, hooks), nil
}

// pipeSDDL returns an owner=sid, protected DACL granting only sid full access.
func pipeSDDL(sid *windows.SID) string {
	s := sid.String()
	return "O:" + s + "D:P(A;;GA;;;" + s + ")"
}

// sidActor derives a stable opaque audit actor from a validated SID.
func sidActor(sid *windows.SID) audit.ID {
	sum := sha256.Sum256(append([]byte("hx/ipc/windows-sid\x00"), sid.String()...))
	var id audit.ID
	copy(id[:], sum[:])
	return id
}

func processUserSID() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tu.User.Sid.Copy()
}

var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// impersonateNamedPipeClient wraps the Win32 API, which golang.org/x/sys
// does not expose.
func impersonateNamedPipeClient(h windows.Handle) error {
	r, _, err := procImpersonateNamedPipeClient.Call(uintptr(h))
	if r == 0 {
		return err
	}
	return nil
}

type fdConn interface{ Fd() uintptr }

// pipePreface is the fixed transport-level byte a client writes immediately
// after connecting. Reading it gives the server a client message whose
// security context ImpersonateNamedPipeClient can adopt.
const pipePreface byte = 0x01

// errClientSIDNotAuthorized distinguishes a valid but unintended client
// token from impersonation or token-access failures.
var errClientSIDNotAuthorized = errors.New("ipc: client SID not authorized")

// authorizePipe consumes the transport preface, impersonates the connected
// client on a locked OS thread, reads the impersonation token user SID, and
// always reverts before the thread is unlocked. A failed revert panics rather
// than continue as the client. No application frame is read here; the
// connection deadline set by the common server bounds the preface read.
func authorizePipe(c net.Conn, want *windows.SID) (audit.ID, error) {
	fc, ok := c.(fdConn)
	if !ok {
		return audit.ID{}, errors.New("ipc: connection is not a named pipe")
	}
	var pre [1]byte
	if _, err := io.ReadFull(c, pre[:]); err != nil {
		return audit.ID{}, fmt.Errorf("ipc: read preface: %w", err)
	}
	if pre[0] != pipePreface {
		return audit.ID{}, errors.New("ipc: invalid transport preface")
	}
	got, err := clientSID(windows.Handle(fc.Fd()))
	if err != nil {
		return audit.ID{}, err
	}
	if !windows.EqualSid(got, want) {
		return audit.ID{}, errClientSIDNotAuthorized
	}
	return sidActor(got), nil
}

func clientSID(h windows.Handle) (*windows.SID, error) {
	runtime.LockOSThread()
	if err := impersonateNamedPipeClient(h); err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("ipc: impersonate client: %w", err)
	}
	var tok windows.Token
	// openAsSelf=true checks access with the process token; anonymous clients
	// have no usable token and are rejected.
	oerr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok)
	if rerr := windows.RevertToSelf(); rerr != nil {
		// Continuing on an impersonating thread is never safe; crash.
		panic(fmt.Sprintf("ipc: RevertToSelf failed: %v", rerr))
	}
	runtime.UnlockOSThread()
	if oerr != nil {
		return nil, fmt.Errorf("ipc: open client token: %w", oerr)
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("ipc: client token user: %w", err)
	}
	return tu.User.Sid.Copy()
}
