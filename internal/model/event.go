// Package model defines the versioned on-disk evidence contract.
package model

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"time"
)

const SchemaVersion = 1
const MaxRecordBytes = 1 << 20

// Event is an immutable observation or a revision of a derived finding.
// ObservedAt is nil when a cache or imported source has unknown freshness.
type Event struct {
	SchemaVersion int            `json:"schema_version"`
	EventID       string         `json:"event_id"`
	RunID         string         `json:"run_id"`
	Seq           uint64         `json:"seq"`
	ObservedAt    *time.Time     `json:"observed_at"`
	RecordedAt    time.Time      `json:"recorded_at"`
	Type          string         `json:"type"`
	RealmID       string         `json:"realm_id"`
	VantageID     string         `json:"vantage_id"`
	RoutingEpoch  uint64         `json:"routing_epoch"`
	EntityID      string         `json:"entity_id,omitempty"`
	Revision      uint64         `json:"revision,omitempty"`
	Prefix        *netip.Prefix  `json:"prefix"`
	Address       string         `json:"address,omitempty"`
	Name          string         `json:"name,omitempty"`
	PrefixBasis   string         `json:"prefix_basis,omitempty"`
	ActivityBasis string         `json:"activity_basis,omitempty"`
	Reachability  string         `json:"reachability,omitempty"`
	Source        string         `json:"source,omitempty"`
	SourceAddress string         `json:"source_address,omitempty"`
	InterfaceID   string         `json:"interface_id,omitempty"`
	Zone          string         `json:"zone,omitempty"`
	Protocol      string         `json:"protocol,omitempty"`
	Port          int            `json:"port,omitempty"`
	Outcome       string         `json:"outcome,omitempty"`
	EvidenceIDs   []string       `json:"evidence_ids,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
}

func NewRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (e Event) Validate() error {
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", e.SchemaVersion)
	}
	if e.RunID == "" || e.Seq == 0 || e.EventID != fmt.Sprintf("%s:%d", e.RunID, e.Seq) {
		return fmt.Errorf("invalid event identity")
	}
	if e.Type == "" || e.RealmID == "" || e.VantageID == "" || e.RecordedAt.IsZero() {
		return fmt.Errorf("missing event metadata")
	}
	if e.Prefix != nil && (!e.Prefix.IsValid() || *e.Prefix != e.Prefix.Masked()) {
		return fmt.Errorf("invalid or noncanonical prefix")
	}
	if e.Type == "finding_upsert" && (e.EntityID == "" || e.Revision == 0 || len(e.EvidenceIDs) == 0) {
		return fmt.Errorf("finding lacks identity, revision or evidence")
	}
	return nil
}

func Now() *time.Time { t := time.Now().UTC(); return &t }

// FindingKey preserves vantage and routing context, including overlapping realms.
func FindingKey(e Event) string {
	return fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%s\x00%s\x00%s\x00%d", e.RealmID, e.VantageID, e.RoutingEpoch, e.EntityID, e.SourceAddress, e.InterfaceID, e.Protocol, e.Port)
}
