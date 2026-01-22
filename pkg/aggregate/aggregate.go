package aggregate

import (
	"math/bits"
	"net/netip"
	"sort"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"
)

// Reusable string constants to avoid allocations
var (
	scopeRange  = "range"
	scenarioAgg = "aggregated"
	duration24h = "24h"
)

// Aggregate takes a list of decisions and returns a new list with IPs aggregated
// into minimal CIDR blocks. Adjacent IPs are merged into larger ranges.
func Aggregate(decisions []*models.Decision) []*models.Decision {
	if len(decisions) == 0 {
		return nil
	}

	// Parse decision values to prefixes
	// Pre-allocate with estimated capacity (most decisions will be valid)
	prefixes := make([]netip.Prefix, 0, len(decisions))
	for _, d := range decisions {
		if d.Value == nil {
			continue
		}
		if p, err := parseValue(*d.Value); err == nil {
			prefixes = append(prefixes, p)
		}
	}

	if len(prefixes) == 0 {
		return nil
	}

	// Aggregate
	aggregated := aggregatePrefixes(prefixes)

	// Convert back to decisions
	result := make([]*models.Decision, 0, len(aggregated))
	for _, p := range aggregated {
		// Always use CIDR notation and "range" scope, even for single IPs
		// This ensures consistency and prevents formatter issues
		val := p.String()

		// Reuse string constants to avoid allocations
		// Use ptr.Of() from go-cs-lib for consistent pointer creation
		result = append(result, &models.Decision{
			Value:    ptr.Of(val),
			Scope:    &scopeRange,
			Scenario: &scenarioAgg,
			Duration: &duration24h,
		})
	}
	return result
}

// parseValue converts a decision value (IP or CIDR) to a netip.Prefix.
func parseValue(value string) (netip.Prefix, error) {
	// Trim leading/trailing whitespace without allocation if possible
	value = strings.TrimSpace(value)

	// Try CIDR notation first (check for '/' without Contains for speed)
	if idx := strings.IndexByte(value, '/'); idx >= 0 {
		return netip.ParsePrefix(value)
	}

	// Single IP - convert to /32 or /128
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}

	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), nil
	}
	return netip.PrefixFrom(addr, 128), nil
}

// aggregatePrefixes takes a list of prefixes and returns a minimal set by:
// 1. Deduplicating
// 2. Sorting by address then prefix length
// 3. Removing prefixes contained within larger prefixes
// 4. Recursively merging adjacent prefixes
func aggregatePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}

	// Deduplicate using map
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, p := range prefixes {
		// Normalize prefix (ensure masked properly)
		seen[p.Masked()] = struct{}{}
	}

	// Convert back to slice
	unique := make([]netip.Prefix, 0, len(seen))
	for p := range seen {
		unique = append(unique, p)
	}

	// Sort by address, then by prefix length (shorter/larger blocks first)
	sortPrefixes(unique)

	// Remove prefixes contained within larger prefixes
	result := removeContained(unique)

	// Recursively merge adjacent prefixes
	result = mergeAdjacent(result)

	return result
}

// sortPrefixes sorts by address, then by prefix length (shorter first).
func sortPrefixes(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(i, j int) bool {
		addrCmp := prefixes[i].Addr().Compare(prefixes[j].Addr())
		if addrCmp != 0 {
			return addrCmp < 0
		}
		// Same address: shorter prefix (smaller bits value = larger block) first
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
}

// removeContained removes prefixes that are contained within a previous larger prefix.
func removeContained(sorted []netip.Prefix) []netip.Prefix {
	if len(sorted) == 0 {
		return nil
	}

	result := make([]netip.Prefix, 0, len(sorted))
	for _, p := range sorted {
		// Check if this prefix is contained in the last added prefix
		if len(result) > 0 {
			last := result[len(result)-1]
			if last.Overlaps(p) && last.Bits() <= p.Bits() {
				// Current prefix is contained in or equal to last, skip it
				continue
			}
		}
		result = append(result, p)
	}
	return result
}

// mergeAdjacent recursively merges adjacent prefixes into parent blocks.
func mergeAdjacent(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) <= 1 {
		return prefixes
	}

	for {
		merged := false
		newResult := make([]netip.Prefix, 0, len(prefixes))

		for i := 0; i < len(prefixes); i++ {
			if i+1 < len(prefixes) {
				if parent, ok := tryMerge(prefixes[i], prefixes[i+1]); ok {
					newResult = append(newResult, parent)
					i++ // Skip next prefix as it was merged
					merged = true
					continue
				}
			}
			newResult = append(newResult, prefixes[i])
		}

		prefixes = newResult
		if !merged {
			break
		}
		// Re-sort and remove contained after merging
		sortPrefixes(prefixes)
		prefixes = removeContained(prefixes)
	}

	return prefixes
}

// tryMerge attempts to merge two prefixes into a parent prefix.
// Returns the parent prefix and true if merge is possible, otherwise zero value and false.
//
// Two prefixes can merge if:
// 1. They have the same prefix length
// 2. They differ by exactly one bit at the expected position
// 3. They form a valid parent prefix
func tryMerge(a, b netip.Prefix) (netip.Prefix, bool) {
	// Must be same prefix length
	if a.Bits() != b.Bits() {
		return netip.Prefix{}, false
	}

	// Can't merge /0
	if a.Bits() == 0 {
		return netip.Prefix{}, false
	}

	// Must be same address family
	if a.Addr().Is4() != b.Addr().Is4() {
		return netip.Prefix{}, false
	}

	if a.Addr().Is4() {
		return tryMergeIPv4(a, b)
	}
	return tryMergeIPv6(a, b)
}

// tryMergeIPv4 attempts to merge two IPv4 prefixes.
func tryMergeIPv4(a, b netip.Prefix) (netip.Prefix, bool) {
	prefixBits := a.Bits()

	// Convert addresses to uint32 for bit operations
	// Use binary.BigEndian for clarity and correctness
	a4 := a.Addr().As4()
	b4 := b.Addr().As4()

	// Convert from network byte order (big-endian) to host byte order
	// This is more efficient than manual bit shifts and clearer than unsafe
	v1 := uint32(a4[0])<<24 | uint32(a4[1])<<16 | uint32(a4[2])<<8 | uint32(a4[3])
	v2 := uint32(b4[0])<<24 | uint32(b4[1])<<16 | uint32(b4[2])<<8 | uint32(b4[3])

	// XOR to find differences
	xor := v1 ^ v2

	// Must differ in exactly one bit (power of 2 check)
	if xor == 0 || (xor&(xor-1)) != 0 {
		return netip.Prefix{}, false
	}

	// Check bit position matches expected merge point
	// The differing bit should be at position (32 - prefixBits) from the right
	bitPos := bits.TrailingZeros32(xor)
	expectedBitPos := 32 - prefixBits
	if bitPos != expectedBitPos {
		return netip.Prefix{}, false
	}

	// Create parent prefix (use the one with 0 at the differing bit)
	parentVal := min(v1, v2)

	// Convert back to network byte order
	parentBytes := [4]byte{
		byte(parentVal >> 24),
		byte(parentVal >> 16),
		byte(parentVal >> 8),
		byte(parentVal),
	}
	parentAddr := netip.AddrFrom4(parentBytes)

	return netip.PrefixFrom(parentAddr, prefixBits-1), true
}

// tryMergeIPv6 attempts to merge two IPv6 prefixes.
func tryMergeIPv6(a, b netip.Prefix) (netip.Prefix, bool) {
	prefixBits := a.Bits()

	a16 := a.Addr().As16()
	b16 := b.Addr().As16()

	// XOR all bytes
	var xor [16]byte
	for i := range 16 {
		xor[i] = a16[i] ^ b16[i]
	}

	// Count total differing bits
	totalDiff := 0
	diffByteIdx := -1
	diffBitInByte := -1

	for i := range 16 {
		if xor[i] != 0 {
			bc := bits.OnesCount8(xor[i])
			totalDiff += bc
			if bc == 1 && diffByteIdx == -1 {
				diffByteIdx = i
				diffBitInByte = 7 - bits.TrailingZeros8(xor[i])
			}
		}
	}

	// Must differ in exactly one bit
	if totalDiff != 1 {
		return netip.Prefix{}, false
	}

	// Check bit position matches expected merge point
	actualBitPos := diffByteIdx*8 + diffBitInByte
	expectedBitPos := prefixBits - 1
	if actualBitPos != expectedBitPos {
		return netip.Prefix{}, false
	}

	// Create parent prefix (use the one with 0 at the differing bit)
	var parent [16]byte
	if a.Addr().Less(b.Addr()) {
		parent = a16
	} else {
		parent = b16
	}
	parentAddr := netip.AddrFrom16(parent)

	return netip.PrefixFrom(parentAddr, prefixBits-1), true
}
