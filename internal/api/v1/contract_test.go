package hxv1_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	hxv1 "github.com/hndrxc/hx/internal/api/v1"
	"github.com/hndrxc/hx/internal/domain"
)

func readFixture(t *testing.T, name string, msg proto.Message) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if err := protojson.Unmarshal(raw, msg); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

func TestMonitoringFixturesRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  proto.Message
	}{
		{"cloud_resources", &hxv1.ListResourcesResponse{}},
		{"homelab_resources", &hxv1.ListResourcesResponse{}},
		{"homelab_observations", &hxv1.ListObservationsResponse{}},
		{"homelab_relationships", &hxv1.ListRelationshipsResponse{}},
		{"homelab_source_statuses", &hxv1.ListSourceStatusesResponse{}},
		{"homelab_events", &hxv1.ListEventsResponse{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			readFixture(t, tc.name, tc.msg)
			json, err := protojson.Marshal(tc.msg)
			if err != nil {
				t.Fatal(err)
			}
			decoded := tc.msg.ProtoReflect().New().Interface()
			if err := protojson.Unmarshal(json, decoded); err != nil || !proto.Equal(decoded, tc.msg) {
				t.Fatalf("JSON round trip: got %v, err %v", decoded, err)
			}
			marshal := proto.MarshalOptions{Deterministic: true}
			wire, err := marshal.Marshal(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if err := proto.Unmarshal(wire, decoded); err != nil || !proto.Equal(decoded, tc.msg) {
				t.Fatalf("binary round trip: got %v, err %v", decoded, err)
			}
			again, err := marshal.Marshal(decoded)
			if err != nil || !bytes.Equal(wire, again) {
				t.Fatalf("binary encoding changed after decode: err %v", err)
			}
		})
	}
}

func TestResourceFixturesDistinguishStates(t *testing.T) {
	for _, tc := range []struct {
		fixture   string
		name      string
		kind      domain.Kind
		status    hxv1.DataStatus
		effective domain.Health
		deleted   bool
	}{
		{"cloud_resources", "api-v42", domain.KindDeployment, hxv1.DataStatus_DATA_STATUS_AVAILABLE, domain.HealthHealthy, false},
		{"cloud_resources", "web-v7", domain.KindDeployment, hxv1.DataStatus_DATA_STATUS_UNAVAILABLE, domain.HealthUnknown, false},
		{"cloud_resources", "legacy-adapter", domain.KindService, hxv1.DataStatus_DATA_STATUS_UNSPECIFIED, domain.HealthUnknown, true},
		{"homelab_resources", "pool-bulk", domain.KindStoragePool, hxv1.DataStatus_DATA_STATUS_AVAILABLE, domain.HealthHealthy, false},
		{"homelab_resources", "pool-cache", domain.KindStoragePool, hxv1.DataStatus_DATA_STATUS_AVAILABLE, domain.HealthUnknown, false},
		{"homelab_resources", "wasabi-archive", domain.KindBackup, hxv1.DataStatus_DATA_STATUS_PERMISSION_DENIED, domain.HealthUnknown, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var page hxv1.ListResourcesResponse
			readFixture(t, tc.fixture, &page)
			var prev string
			var record *hxv1.Resource
			for _, r := range page.GetResources() {
				if r.GetId() <= prev {
					t.Fatal("fixture resources are not strictly ordered by ID")
				}
				prev = r.GetId()
				if r.GetDisplayName() == tc.name {
					record = r
				}
			}
			if record == nil {
				t.Fatalf("missing %s", tc.name)
			}
			source := record.GetSource()
			id, err := domain.NewResourceID(domain.Source{IntegrationID: source.GetIntegrationId(), Scope: source.GetScope()}, tc.kind, tc.name)
			if err != nil || string(id) != record.GetId() || hxv1.Kind(tc.kind) != record.GetKind() {
				t.Fatalf("resource identity: expected %s matching %v; err %v", id, record, err)
			}
			state := record.GetState()
			if tc.deleted {
				if record.GetTombstonedAt() == nil || state != nil {
					t.Fatalf("tombstone carried active state: %v", record)
				}
				return
			}
			at := state.GetObservedAt()
			if record.GetTombstonedAt() != nil || at == nil || state.GetDataStatus() != tc.status {
				t.Fatalf("wrong active state or availability: %v", record)
			}
			observed := domain.State{
				DataStatus: domain.DataStatus(state.GetDataStatus()),
				Health:     domain.Health(state.GetHealth()),
				Freshness:  domain.Freshness(state.GetFreshness()),
				ObservedAt: at.AsTime(),
			}
			if got := observed.EffectiveHealth(); got != tc.effective {
				t.Fatalf("effective health = %v, want %v", got, tc.effective)
			}
		})
	}
}

func TestObservationFixtureDistinguishesZeroFromDenied(t *testing.T) {
	var page hxv1.ListObservationsResponse
	readFixture(t, "homelab_observations", &page)
	byName := make(map[string]*hxv1.Observation)
	for _, observation := range page.GetObservations() {
		if ts := observation.GetObservedAt(); ts == nil || !ts.IsValid() {
			t.Fatalf("observation missing a valid timestamp: %v", observation)
		}
		byName[observation.GetName()] = observation
	}
	zero := byName["failed_drives"]
	if v, ok := zero.GetValue().(*hxv1.Observation_IntValue); !ok || v.IntValue != 0 ||
		zero.GetState() != hxv1.DataStatus_DATA_STATUS_AVAILABLE || zero.GetUnit() != hxv1.Unit_UNIT_COUNT {
		t.Fatalf("measured zero did not survive fixture decode: %v", zero)
	}
	denied := byName["sync_lag_seconds"]
	if denied.GetState() != hxv1.DataStatus_DATA_STATUS_PERMISSION_DENIED ||
		denied.GetUnit() != hxv1.Unit_UNIT_UNSPECIFIED || denied.GetValue() != nil {
		t.Fatalf("permission denied must not invent a numeric value or unit: %v", denied)
	}
}

func TestPartialSourceRetainsPreviousSuccess(t *testing.T) {
	var page hxv1.ListSourceStatusesResponse
	readFixture(t, "homelab_source_statuses", &page)
	for _, status := range page.GetStatuses() {
		if status.GetSource().GetIntegrationId() != "homelab-node2" {
			continue
		}
		lastSuccess, lastAttempt := status.GetLastSuccessAt(), status.GetLastAttemptAt()
		if status.GetOutcome() != hxv1.Outcome_OUTCOME_PARTIAL || lastSuccess == nil || lastAttempt == nil ||
			!lastSuccess.AsTime().Before(lastAttempt.AsTime()) {
			t.Fatalf("partial poll lost its previous complete attempt: %v", status)
		}
		return
	}
	t.Fatal("fixture is missing the partial source status")
}

func TestTombstonedAtEpochStillHasPresence(t *testing.T) {
	raw, err := proto.Marshal(&hxv1.Resource{TombstonedAt: timestamppb.New(time.Unix(0, 0))})
	if err != nil {
		t.Fatal(err)
	}
	var resource hxv1.Resource
	if err := proto.Unmarshal(raw, &resource); err != nil {
		t.Fatal(err)
	}
	if at := resource.GetTombstonedAt(); at == nil || !at.AsTime().Equal(time.Unix(0, 0)) {
		t.Fatalf("tombstone timestamp at Unix epoch lost presence: %v", at)
	}
}

func TestMonitoringV1RPCNamesAndCardinality(t *testing.T) {
	service := hxv1.File_hx_v1_monitoring_service_proto.Services().ByName("MonitoringService")
	if service == nil || service.FullName() != "hx.v1.MonitoringService" {
		t.Fatalf("missing hx.v1.MonitoringService: %v", service)
	}
	for _, name := range []protoreflect.Name{"GetResource", "ListResources", "ListObservations", "ListEvents", "ListRelationships", "ListSourceStatuses"} {
		method := service.Methods().ByName(name)
		if method == nil || method.IsStreamingClient() || method.IsStreamingServer() {
			t.Fatalf("%s is missing or no longer unary", name)
		}
	}
}
