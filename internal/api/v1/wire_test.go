package hxv1_test

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	hxv1 "github.com/hndrxc/hx/internal/api/v1"
)

// Hand-computed wire bytes for a fully populated Resource:
//
//	1 id              "r1_vec"
//	2 kind            3 (KIND_DEPLOYMENT)
//	3 source          {integration_id: "cloud-alpha", scope: "prod/us-east-1"}
//	4 display_name    "api-v42"
//	5 state           {data_status: 1, health: 1, freshness: 1,
//	                   observed_at: 2026-11-25T09:30:00Z}
//	6 tombstoned_at   2026-11-25T09:30:00Z
const rawResourceHex = "0a0672315f76656310031a1d0a0b636c6f75642d616c706861120e70726f642f75732d656173742d3122076170692d7634322a0e08011001180122060898d59ad80632060898d59ad806"

// Hand-computed wire bytes for a fully populated Observation:
//
//	1 resource_id  "r1_obs"
//	2 name         "used_bytes"
//	3 state        1 (DATA_STATUS_AVAILABLE)
//	4 unit         2 (UNIT_BYTES)
//	5 int_value    137438953472
//	7 observed_at  2026-11-25T09:30:00Z
const rawObservationHex = "0a0672315f6f6273120a757365645f627974657318012002288080808080043a060898d59ad806"

// Unknown field 12345 (wire type 2) carrying "legacy", simulating data
// written by an older wire speaker.
const rawUnknownChunkHex = "ca8306066c6567616379"

const rawResourceUnknownHex = rawResourceHex + rawUnknownChunkHex

func decodeHex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

func TestKnownWireTagsResource(t *testing.T) {
	raw := decodeHex(t, rawResourceHex)
	var r hxv1.Resource
	if err := proto.Unmarshal(raw, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := &hxv1.Resource{
		Id:          "r1_vec",
		Kind:        hxv1.Kind_KIND_DEPLOYMENT,
		Source:      &hxv1.Source{IntegrationId: "cloud-alpha", Scope: "prod/us-east-1"},
		DisplayName: "api-v42",
		State: &hxv1.State{
			DataStatus: hxv1.DataStatus_DATA_STATUS_AVAILABLE,
			Health:     hxv1.Health_HEALTH_HEALTHY,
			Freshness:  hxv1.Freshness_FRESHNESS_FRESH,
			ObservedAt: timestamppb.New(time.Unix(1795599000, 0)),
		},
		TombstonedAt: timestamppb.New(time.Unix(1795599000, 0)),
	}
	if !proto.Equal(&r, want) {
		t.Fatalf("decoded resource mismatch:\n got: %v\nwant: %v", &r, want)
	}
}

func TestKnownWireTagsObservation(t *testing.T) {
	raw := decodeHex(t, rawObservationHex)
	var o hxv1.Observation
	if err := proto.Unmarshal(raw, &o); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := &hxv1.Observation{
		ResourceId: "r1_obs",
		Name:       "used_bytes",
		State:      hxv1.DataStatus_DATA_STATUS_AVAILABLE,
		Unit:       hxv1.Unit_UNIT_BYTES,
		Value:      &hxv1.Observation_IntValue{IntValue: 137438953472},
		ObservedAt: timestamppb.New(time.Unix(1795599000, 0)),
	}
	if !proto.Equal(&o, want) {
		t.Fatalf("decoded observation mismatch:\n got: %v\nwant: %v", &o, want)
	}
}

// TestUnknownFieldPreservation verifies unknown fields from older or newer
// speakers survive a binary round trip while known fields stay readable.
func TestUnknownFieldPreservation(t *testing.T) {
	raw := decodeHex(t, rawResourceUnknownHex)
	var r hxv1.Resource
	if err := proto.Unmarshal(raw, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.GetId() != "r1_vec" {
		t.Fatalf("known fields lost behind unknown field: %v", &r)
	}
	out, err := proto.Marshal(&r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded hxv1.Resource
	if err := proto.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	if got, want := decoded.ProtoReflect().GetUnknown(), decodeHex(t, rawUnknownChunkHex); !bytes.Equal(got, want) {
		t.Fatalf("unknown field not preserved: got %x, want %x", got, want)
	}
}
