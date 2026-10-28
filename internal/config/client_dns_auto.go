// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package config

import (
	"fmt"
	"math"
	"strings"
)

// finalizeDNSAutoConfig validates the adaptive query-type selection policy.
func finalizeDNSAutoConfig(cfg *ClientConfig) error {
	if len(cfg.DNSAutoQueryTypes) == 0 {
		return fmt.Errorf("DNS_AUTO_QUERY_TYPES must contain at least one of TXT, NS, CNAME, SRV")
	}
	types := make([]string, 0, 4)
	seen := make(map[string]bool, 4)
	for _, value := range cfg.DNSAutoQueryTypes {
		name := strings.ToUpper(strings.TrimSpace(value))
		switch name {
		case "TXT", "NS", "CNAME", "SRV":
		default:
			return fmt.Errorf("invalid DNS_AUTO_QUERY_TYPES entry: %q (allowed: TXT, NS, CNAME, SRV)", value)
		}
		if !seen[name] {
			types = append(types, name)
			seen[name] = true
		}
	}
	cfg.DNSAutoQueryTypes = types

	for _, setting := range []struct {
		name  string
		value int
		min   int
		max   int
	}{
		{"DNS_AUTO_PROBE_COUNT", cfg.DNSAutoProbeCount, 1, 100},
		{"DNS_AUTO_SWITCH_CONFIRMATION_COUNT", cfg.DNSAutoSwitchConfirmationCount, 0, 100},
		{"DNS_AUTO_RECHECK_PARALLELISM", cfg.DNSAutoRecheckParallelism, 1, 1024},
		{"DNS_AUTO_FAILURE_THRESHOLD", cfg.DNSAutoFailureThreshold, 1, 10000},
	} {
		if setting.value < setting.min || setting.value > setting.max {
			return fmt.Errorf("%s must be between %d and %d (got %d)", setting.name, setting.min, setting.max, setting.value)
		}
	}

	for _, setting := range []struct {
		name  string
		value float64
		min   float64
		max   float64
	}{
		{"DNS_AUTO_PROBE_TIMEOUT_SECONDS", cfg.DNSAutoProbeTimeoutSeconds, 0, 600},
		{"DNS_AUTO_MIN_SUCCESS_PERCENT", cfg.DNSAutoMinSuccessPercent, 0, 100},
		{"DNS_AUTO_MIN_SPEED_IMPROVEMENT_PERCENT", cfg.DNSAutoMinSpeedImprovementPercent, 0, 1000},
		{"DNS_AUTO_RECHECK_INTERVAL_SECONDS", cfg.DNSAutoRecheckIntervalSeconds, 60, 86400},
		{"DNS_AUTO_RECHECK_JITTER_PERCENT", cfg.DNSAutoRecheckJitterPercent, 0, 50},
		{"DNS_AUTO_FAILURE_RECHECK_COOLDOWN_SECONDS", cfg.DNSAutoFailureRecheckCooldownSeconds, 0, 86400},
	} {
		if math.IsNaN(setting.value) || math.IsInf(setting.value, 0) || setting.value < setting.min || setting.value > setting.max {
			return fmt.Errorf("%s must be finite and between %g and %g (got %g)", setting.name, setting.min, setting.max, setting.value)
		}
	}
	if cfg.DNSAutoMinSuccessPercent == 0 {
		return fmt.Errorf("DNS_AUTO_MIN_SUCCESS_PERCENT must be greater than 0")
	}
	return nil
}
