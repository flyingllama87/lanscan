package platform

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// NRPT rules live under these keys; Group Policy rules take precedence, and
// while any exist the locally configured rules are not applied.
var nrptKeys = []struct{ path, source string }{
	{`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`, "group_policy"},
	{`SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`, "local"},
}

// NRPTRules reads configured rules from the registry. It sends no queries.
func NRPTRules() (rules []NRPTRule, effective string, err error) {
	for _, k := range nrptKeys {
		parent, err := registry.OpenKey(registry.LOCAL_MACHINE, k.path, registry.ENUMERATE_SUB_KEYS)
		if err == registry.ErrNotExist {
			continue
		}
		if err != nil {
			return rules, effective, err
		}
		names, err := parent.ReadSubKeyNames(0)
		parent.Close()
		if err != nil {
			return rules, effective, err
		}
		for _, name := range names {
			key, err := registry.OpenKey(registry.LOCAL_MACHINE, k.path+`\`+name, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			r := NRPTRule{Key: name, Source: k.source}
			r.Namespaces, _, _ = key.GetStringsValue("Name")
			if servers, _, err := key.GetStringValue("GenericDNSServers"); err == nil {
				for _, s := range strings.Split(servers, ";") {
					if s = strings.TrimSpace(s); s != "" {
						r.Servers = append(r.Servers, s)
					}
				}
			}
			if v, _, err := key.GetIntegerValue("ConfigOptions"); err == nil {
				r.Options = uint32(v)
			}
			key.Close()
			if len(r.Namespaces) > 0 {
				rules = append(rules, r)
			}
		}
		if effective == "" && len(rules) > 0 {
			effective = k.source
		}
	}
	return rules, effective, nil
}

// effectiveNRPT returns the rules Windows applies.
func effectiveNRPT() ([]NRPTRule, error) {
	rules, effective, err := NRPTRules()
	var out []NRPTRule
	for _, r := range rules {
		if r.Source == effective {
			out = append(out, r)
		}
	}
	return out, err
}

// DNSPolicyDetails records which NRPT rule governs a system-policy query name.
func DNSPolicyDetails(name string) map[string]any {
	rules, err := effectiveNRPT()
	if err != nil {
		return map[string]any{"nrpt": "unreadable", "nrpt_error": err.Error()}
	}
	r, ns, ok := MatchNRPT(name, rules)
	if !ok {
		return map[string]any{"nrpt": "no_configured_rule_matches"}
	}
	// This is the configured rule, not Windows' effective decision: Server 2016
	// was seen to apply a rule's servers to only some of its namespaces.
	d := map[string]any{"nrpt": "configured_rule_matches", "nrpt_namespace": ns, "nrpt_source": r.Source, "nrpt_rule": r.Key, "nrpt_match": "longest namespace match computed by lanscan from configured rules; the DNS client applies its own effective policy"}
	if len(r.Servers) > 0 {
		d["nrpt_servers"] = r.Servers
	}
	return d
}
