package domain

import "testing"

// The IDs below are canonical fixtures of the D01 stable-ID agreement shared
// with proto/hx/v1 (the wire contract). They lock the exact byte layout:
//
//	r1_ + hex(sha256("hx.resource.v1\x00" ||
//	     frame(integrationID) || frame(scope) || frame(kind) || frame(nativeKey)))
//
// with frame(x) = uint32 big-endian length + UTF-8 bytes. Recompute with the
// same algorithm in any language; do not change these values without updating
// the wire contract fixture.

func TestContractResourceIDFixtures(t *testing.T) {
	src := Source{IntegrationID: "acct-01", Scope: "us-east-1"}
	const key = "proj-9f8e7d6c5b4a3"
	const wantProject = "r1_0eb03f5ec27754fb6a06f7db0b736c28b3ef06d801eedafccdf2e7d2058672dd"
	const wantStoragePool = "r1_35d5d8a762dd0bb5486c0cb76ce8273042c09ca84a1d141fc7a6043b480ada55"

	pid, err := NewResourceID(src, KindProject, key)
	if err != nil {
		t.Fatal(err)
	}
	if pid != wantProject {
		t.Errorf("project fixture:\n got %s\nwant %s", pid, wantProject)
	}

	sid, err := NewResourceID(src, KindStoragePool, key)
	if err != nil {
		t.Fatal(err)
	}
	if sid != wantStoragePool {
		t.Errorf("storage_pool fixture:\n got %s\nwant %s", sid, wantStoragePool)
	}

	if pid == sid {
		t.Error("project and storage_pool fixtures must differ")
	}
}
