//go:build windows && !(amd64 || arm64)

package platform

import "net"

// SystemResolver keeps the Go resolver on 32-bit Windows, where the
// DnsQueryEx structure layouts are not mirrored.
func SystemResolver() (Resolver, string) { return net.DefaultResolver, "system" }
