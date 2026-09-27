package app

import "testing"

func TestStopOutcomePrecedence(t *testing.T) {
	statuses := map[string]string{"routes": "complete", "icmp4": "available", "dns_cache": "denied"}
	for _, tc := range []struct {
		name   string
		in     stopOutcome
		code   int
		reason string
	}{
		{"completed", stopOutcome{validation: "completed", statuses: statuses}, 0, "completed"},
		{"validation reason", stopOutcome{validation: "operation_budget_exhausted"}, 3, "operation_budget_exhausted"},
		{"capacity beats validation", stopOutcome{validation: "operation_budget_exhausted", dropped: 1}, 3, "capacity_exceeded"},
		{"required available", stopOutcome{validation: "completed", required: []string{"routes", "icmp4"}, statuses: statuses}, 0, "completed"},
		{"required denied", stopOutcome{validation: "completed", required: []string{"dns_cache"}, statuses: statuses}, 3, "required_capability_unavailable"},
		{"required missing", stopOutcome{validation: "completed", required: []string{"absent"}, statuses: statuses}, 3, "required_capability_unavailable"},
		{"deadline beats capability", stopOutcome{validation: "completed", required: []string{"absent"}, deadline: true}, 3, "duration_exhausted"},
		{"interrupt beats all", stopOutcome{validation: "operation_budget_exhausted", dropped: 1, deadline: true, interrupt: true}, 130, "interrupted"},
	} {
		code, reason := tc.in.resolve()
		if code != tc.code || reason != tc.reason {
			t.Errorf("%s: got %d %s, want %d %s", tc.name, code, reason, tc.code, tc.reason)
		}
	}
}
