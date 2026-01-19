package aggregate

import (
	"net/netip"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptr(s string) *string {
	return &s
}

func TestParseValue(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    netip.Prefix
		wantErr bool
	}{
		{
			name:  "IPv4 single",
			input: "192.168.1.1",
			want:  netip.MustParsePrefix("192.168.1.1/32"),
		},
		{
			name:  "IPv4 CIDR",
			input: "10.0.0.0/8",
			want:  netip.MustParsePrefix("10.0.0.0/8"),
		},
		{
			name:  "IPv6 single",
			input: "2001:db8::1",
			want:  netip.MustParsePrefix("2001:db8::1/128"),
		},
		{
			name:  "IPv6 CIDR",
			input: "2001:db8::/32",
			want:  netip.MustParsePrefix("2001:db8::/32"),
		},
		{
			name:    "invalid",
			input:   "not-an-ip",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseValue(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTryMergeIPv4(t *testing.T) {
	tests := []struct {
		name   string
		a      string
		b      string
		want   string
		canMrg bool
	}{
		{
			name:   "adjacent /32s merge to /31",
			a:      "10.0.0.0/32",
			b:      "10.0.0.1/32",
			want:   "10.0.0.0/31",
			canMrg: true,
		},
		{
			name:   "adjacent /32s merge to /31 (reversed order)",
			a:      "10.0.0.1/32",
			b:      "10.0.0.0/32",
			want:   "10.0.0.0/31",
			canMrg: true,
		},
		{
			name:   "non-adjacent /32s don't merge",
			a:      "10.0.0.0/32",
			b:      "10.0.0.2/32",
			canMrg: false,
		},
		{
			name:   "adjacent /24s merge to /23",
			a:      "192.168.0.0/24",
			b:      "192.168.1.0/24",
			want:   "192.168.0.0/23",
			canMrg: true,
		},
		{
			name:   "non-adjacent /24s don't merge",
			a:      "192.168.0.0/24",
			b:      "192.168.2.0/24",
			canMrg: false,
		},
		{
			name:   "different prefix lengths don't merge",
			a:      "10.0.0.0/24",
			b:      "10.0.1.0/25",
			canMrg: false,
		},
		{
			name:   "adjacent /31s merge to /30",
			a:      "192.168.0.0/31",
			b:      "192.168.0.2/31",
			want:   "192.168.0.0/30",
			canMrg: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := netip.MustParsePrefix(tt.a)
			b := netip.MustParsePrefix(tt.b)

			got, ok := tryMerge(a, b)
			assert.Equal(t, tt.canMrg, ok)
			if tt.canMrg {
				assert.Equal(t, tt.want, got.String())
			}
		})
	}
}

func TestTryMergeIPv6(t *testing.T) {
	tests := []struct {
		name   string
		a      string
		b      string
		want   string
		canMrg bool
	}{
		{
			name:   "adjacent /128s merge to /127",
			a:      "2001:db8::0/128",
			b:      "2001:db8::1/128",
			want:   "2001:db8::/127",
			canMrg: true,
		},
		{
			name:   "non-adjacent /128s don't merge",
			a:      "2001:db8::0/128",
			b:      "2001:db8::2/128",
			canMrg: false,
		},
		{
			name:   "adjacent /64s merge to /63",
			a:      "2001:db8::/64",
			b:      "2001:db8:0:1::/64",
			want:   "2001:db8::/63",
			canMrg: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := netip.MustParsePrefix(tt.a)
			b := netip.MustParsePrefix(tt.b)

			got, ok := tryMerge(a, b)
			assert.Equal(t, tt.canMrg, ok)
			if tt.canMrg {
				assert.Equal(t, tt.want, got.String())
			}
		})
	}
}

func TestAggregatePrefixes(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect []string
	}{
		{
			name:   "empty input",
			input:  []string{},
			expect: nil,
		},
		{
			name:   "single IP",
			input:  []string{"10.0.0.1/32"},
			expect: []string{"10.0.0.1/32"},
		},
		{
			name:   "two adjacent IPs merge",
			input:  []string{"10.0.0.0/32", "10.0.0.1/32"},
			expect: []string{"10.0.0.0/31"},
		},
		{
			name:   "two non-adjacent IPs don't merge",
			input:  []string{"10.0.0.0/32", "10.0.0.2/32"},
			expect: []string{"10.0.0.0/32", "10.0.0.2/32"},
		},
		{
			name:   "four consecutive IPs merge to /30",
			input:  []string{"10.0.0.0/32", "10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32"},
			expect: []string{"10.0.0.0/30"},
		},
		{
			name:   "overlapping - larger block absorbs smaller",
			input:  []string{"10.0.0.0/24", "10.0.0.5/32", "10.0.0.10/32"},
			expect: []string{"10.0.0.0/24"},
		},
		{
			name:   "duplicates removed",
			input:  []string{"10.0.0.1/32", "10.0.0.1/32", "10.0.0.1/32"},
			expect: []string{"10.0.0.1/32"},
		},
		{
			name:   "full /24 from 256 IPs",
			input:  generateConsecutiveIPs("10.1.0.0", 256),
			expect: []string{"10.1.0.0/24"},
		},
		{
			name:   "mixed IPv4 and IPv6",
			input:  []string{"10.0.0.0/32", "10.0.0.1/32", "2001:db8::0/128", "2001:db8::1/128"},
			expect: []string{"10.0.0.0/31", "2001:db8::/127"},
		},
		{
			name: "partial merge - 3 consecutive IPs",
			input: []string{
				"192.168.0.1/32",
				"192.168.0.2/32",
				"192.168.0.3/32",
			},
			expect: []string{"192.168.0.1/32", "192.168.0.2/31"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var prefixes []netip.Prefix
			for _, s := range tt.input {
				prefixes = append(prefixes, netip.MustParsePrefix(s))
			}

			got := aggregatePrefixes(prefixes)

			var gotStrings []string
			for _, p := range got {
				gotStrings = append(gotStrings, p.String())
			}

			assert.Equal(t, tt.expect, gotStrings)
		})
	}
}

func TestAggregate(t *testing.T) {
	tests := []struct {
		name   string
		input  []*models.Decision
		expect []string
	}{
		{
			name:   "nil input",
			input:  nil,
			expect: nil,
		},
		{
			name:   "empty input",
			input:  []*models.Decision{},
			expect: nil,
		},
		{
			name: "single IP decision",
			input: []*models.Decision{
				{Value: ptr("10.0.0.1")},
			},
			expect: []string{"10.0.0.1/32"},
		},
		{
			name: "adjacent IPs merge",
			input: []*models.Decision{
				{Value: ptr("10.0.0.0")},
				{Value: ptr("10.0.0.1")},
			},
			expect: []string{"10.0.0.0/31"},
		},
		{
			name: "CIDR decisions",
			input: []*models.Decision{
				{Value: ptr("10.0.0.0/24")},
				{Value: ptr("10.0.1.0/24")},
			},
			expect: []string{"10.0.0.0/23"},
		},
		{
			name: "nil value skipped",
			input: []*models.Decision{
				{Value: ptr("10.0.0.0")},
				{Value: nil},
				{Value: ptr("10.0.0.1")},
			},
			expect: []string{"10.0.0.0/31"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Aggregate(tt.input)

			if tt.expect == nil {
				assert.Nil(t, got)
				return
			}

			var gotStrings []string
			for _, d := range got {
				gotStrings = append(gotStrings, *d.Value)
			}

			assert.Equal(t, tt.expect, gotStrings)
		})
	}
}

func TestAggregateScope(t *testing.T) {
	// Test that scope is set correctly
	input := []*models.Decision{
		{Value: ptr("10.0.0.0")},
		{Value: ptr("10.0.0.1")},
		{Value: ptr("192.168.1.1")},
	}

	got := Aggregate(input)
	require.Len(t, got, 2)

	// 10.0.0.0/31 should be "range"
	assert.Equal(t, "10.0.0.0/31", *got[0].Value)
	assert.Equal(t, "range", *got[0].Scope)

	// 192.168.1.1/32 should be "Ip"
	assert.Equal(t, "192.168.1.1/32", *got[1].Value)
	assert.Equal(t, "Ip", *got[1].Scope)
}

// generateConsecutiveIPs generates n consecutive IPs starting from start
func generateConsecutiveIPs(start string, n int) []string {
	addr := netip.MustParseAddr(start)
	result := make([]string, n)
	for i := range n {
		result[i] = addr.String() + "/32"
		addr = addr.Next()
	}
	return result
}

func BenchmarkAggregatePrefixes(b *testing.B) {
	// Generate 1000 random-ish IPs
	var prefixes []netip.Prefix
	base := netip.MustParseAddr("10.0.0.0")
	for i := range 1000 {
		addr := base
		for range i {
			addr = addr.Next()
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, 32))
	}

	b.ResetTimer()
	for range b.N {
		aggregatePrefixes(prefixes)
	}
}

func BenchmarkAggregate256Consecutive(b *testing.B) {
	// Best case: 256 consecutive IPs that merge to /24
	var decisions []*models.Decision
	base := netip.MustParseAddr("10.1.0.0")
	for i := range 256 {
		addr := base
		for range i {
			addr = addr.Next()
		}
		val := addr.String()
		decisions = append(decisions, &models.Decision{Value: &val})
	}

	b.ResetTimer()
	for range b.N {
		Aggregate(decisions)
	}
}
