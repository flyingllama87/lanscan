package platform

import "net"

// SystemResolver returns the resolver for "system" policy DNS. With
// systemd-resolved the stub applies per-link routing domains.
func SystemResolver() (Resolver, string) { return net.DefaultResolver, "system" }

// DNSPolicyDetails has nothing to add on Linux: per-link routing is recorded
// by the resolver_config collector.
func DNSPolicyDetails(string) map[string]any { return nil }
