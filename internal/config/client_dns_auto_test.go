// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package config

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeDNSAutoConfigFile(t *testing.T, settings string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "client_config.toml")
	body := "DOMAINS = [\"v.example.com\"]\nENCRYPTION_KEY = \"test-key\"\n" + settings
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte("127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertDNSAutoFields(t *testing.T, cfg ClientConfig, want map[string]any) {
	t.Helper()
	value := reflect.ValueOf(cfg)
	for name, expected := range want {
		field := value.FieldByName(name)
		if !field.IsValid() {
			t.Errorf("config does not expose %s", name)
			continue
		}
		if got := field.Interface(); !reflect.DeepEqual(got, expected) {
			t.Errorf("%s = %#v, want %#v", name, got, expected)
		}
	}
}

func TestClientConfigDNSAutoDefaults(t *testing.T) {
	cfg, err := LoadClientConfig(writeDNSAutoConfigFile(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	assertDNSAutoFields(t, cfg, map[string]any{
		"DNSAutoQueryTypes":                    []string{"TXT", "NS", "CNAME", "SRV"},
		"DNSAutoProbeCount":                    5,
		"DNSAutoProbeTimeoutSeconds":           0.0,
		"DNSAutoMinSuccessPercent":             20.0,
		"DNSAutoSwitchConfirmationCount":       5,
		"DNSAutoMinSpeedImprovementPercent":    20.0,
		"DNSAutoRecheckEnabled":                true,
		"DNSAutoRecheckIntervalSeconds":        900.0,
		"DNSAutoRecheckParallelism":            2,
		"DNSAutoRecheckJitterPercent":          10.0,
		"DNSAutoFailureRecheckEnabled":         true,
		"DNSAutoFailureThreshold":              3,
		"DNSAutoFailureRecheckCooldownSeconds": 30.0,
		"DNSAutoAllowMTURestart":               true,
	})
	if cfg.DNSQueryType != "TXT" {
		t.Fatalf("existing default query type changed to %q", cfg.DNSQueryType)
	}
}

func TestClientConfigDNSAutoLoadsAndNormalizesSettings(t *testing.T) {
	cfg, err := LoadClientConfig(writeDNSAutoConfigFile(t, `
DNS_AUTO_QUERY_TYPES = [" srv ", "txt", "SRV", " ns "]
DNS_AUTO_PROBE_COUNT = 10
DNS_AUTO_PROBE_TIMEOUT_SECONDS = 3.5
DNS_AUTO_MIN_SUCCESS_PERCENT = 70.0
DNS_AUTO_SWITCH_CONFIRMATION_COUNT = 8
DNS_AUTO_MIN_SPEED_IMPROVEMENT_PERCENT = 35.0
DNS_AUTO_RECHECK_ENABLED = false
DNS_AUTO_RECHECK_INTERVAL_SECONDS = 1800.0
DNS_AUTO_RECHECK_PARALLELISM = 4
DNS_AUTO_RECHECK_JITTER_PERCENT = 25.0
DNS_AUTO_FAILURE_RECHECK_ENABLED = false
DNS_AUTO_FAILURE_THRESHOLD = 6
DNS_AUTO_FAILURE_RECHECK_COOLDOWN_SECONDS = 60.0
DNS_AUTO_ALLOW_MTU_RESTART = false
`))
	if err != nil {
		t.Fatal(err)
	}
	assertDNSAutoFields(t, cfg, map[string]any{
		"DNSAutoQueryTypes":                    []string{"SRV", "TXT", "NS"},
		"DNSAutoProbeCount":                    10,
		"DNSAutoProbeTimeoutSeconds":           3.5,
		"DNSAutoMinSuccessPercent":             70.0,
		"DNSAutoSwitchConfirmationCount":       8,
		"DNSAutoMinSpeedImprovementPercent":    35.0,
		"DNSAutoRecheckEnabled":                false,
		"DNSAutoRecheckIntervalSeconds":        1800.0,
		"DNSAutoRecheckParallelism":            4,
		"DNSAutoRecheckJitterPercent":          25.0,
		"DNSAutoFailureRecheckEnabled":         false,
		"DNSAutoFailureThreshold":              6,
		"DNSAutoFailureRecheckCooldownSeconds": 60.0,
		"DNSAutoAllowMTURestart":               false,
	})
}

func TestClientConfigRejectsInvalidDNSAutoSettings(t *testing.T) {
	cases := []struct {
		key   string
		value string
	}{
		{"DNS_AUTO_QUERY_TYPES", "[]"},
		{"DNS_AUTO_QUERY_TYPES", `["TXT", "AUTO"]`},
		{"DNS_AUTO_QUERY_TYPES", `["RANDOM"]`},
		{"DNS_AUTO_QUERY_TYPES", `["A"]`},
		{"DNS_AUTO_QUERY_TYPES", `[" "]`},
		{"DNS_AUTO_PROBE_COUNT", "0"},
		{"DNS_AUTO_PROBE_COUNT", "101"},
		{"DNS_AUTO_PROBE_TIMEOUT_SECONDS", "-0.1"},
		{"DNS_AUTO_PROBE_TIMEOUT_SECONDS", "600.1"},
		{"DNS_AUTO_MIN_SUCCESS_PERCENT", "0.0"},
		{"DNS_AUTO_MIN_SUCCESS_PERCENT", "100.1"},
		{"DNS_AUTO_SWITCH_CONFIRMATION_COUNT", "-1"},
		{"DNS_AUTO_SWITCH_CONFIRMATION_COUNT", "101"},
		{"DNS_AUTO_MIN_SPEED_IMPROVEMENT_PERCENT", "-0.1"},
		{"DNS_AUTO_MIN_SPEED_IMPROVEMENT_PERCENT", "1000.1"},
		{"DNS_AUTO_RECHECK_INTERVAL_SECONDS", "59.9"},
		{"DNS_AUTO_RECHECK_INTERVAL_SECONDS", "86400.1"},
		{"DNS_AUTO_RECHECK_PARALLELISM", "0"},
		{"DNS_AUTO_RECHECK_PARALLELISM", "1025"},
		{"DNS_AUTO_RECHECK_JITTER_PERCENT", "-0.1"},
		{"DNS_AUTO_RECHECK_JITTER_PERCENT", "50.1"},
		{"DNS_AUTO_FAILURE_THRESHOLD", "0"},
		{"DNS_AUTO_FAILURE_THRESHOLD", "10001"},
		{"DNS_AUTO_FAILURE_RECHECK_COOLDOWN_SECONDS", "-0.1"},
		{"DNS_AUTO_FAILURE_RECHECK_COOLDOWN_SECONDS", "86400.1"},
	}
	floatKeys := []string{
		"DNS_AUTO_PROBE_TIMEOUT_SECONDS", "DNS_AUTO_MIN_SUCCESS_PERCENT",
		"DNS_AUTO_MIN_SPEED_IMPROVEMENT_PERCENT", "DNS_AUTO_RECHECK_INTERVAL_SECONDS",
		"DNS_AUTO_RECHECK_JITTER_PERCENT", "DNS_AUTO_FAILURE_RECHECK_COOLDOWN_SECONDS",
	}
	for _, key := range floatKeys {
		for _, value := range []string{"nan", "+inf", "-inf"} {
			cases = append(cases, struct{ key, value string }{key, value})
		}
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			_, err := LoadClientConfig(writeDNSAutoConfigFile(t, tc.key+" = "+tc.value+"\n"))
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("want validation error naming %s, got %v", tc.key, err)
			}
		})
	}
}

func TestClientConfigDNSAutoAcceptsLimitsAndExplicitZero(t *testing.T) {
	for name, settings := range map[string]string{
		"minimums": `
DNS_AUTO_QUERY_TYPES = ["TXT"]
DNS_AUTO_PROBE_COUNT = 1
DNS_AUTO_PROBE_TIMEOUT_SECONDS = 0.0
DNS_AUTO_MIN_SUCCESS_PERCENT = 0.1
DNS_AUTO_SWITCH_CONFIRMATION_COUNT = 0
DNS_AUTO_MIN_SPEED_IMPROVEMENT_PERCENT = 0.0
DNS_AUTO_RECHECK_INTERVAL_SECONDS = 60.0
DNS_AUTO_RECHECK_PARALLELISM = 1
DNS_AUTO_RECHECK_JITTER_PERCENT = 0.0
DNS_AUTO_FAILURE_THRESHOLD = 1
DNS_AUTO_FAILURE_RECHECK_COOLDOWN_SECONDS = 0.0
`,
		"maximums": `
DNS_AUTO_PROBE_COUNT = 100
DNS_AUTO_PROBE_TIMEOUT_SECONDS = 600.0
DNS_AUTO_MIN_SUCCESS_PERCENT = 100.0
DNS_AUTO_SWITCH_CONFIRMATION_COUNT = 100
DNS_AUTO_MIN_SPEED_IMPROVEMENT_PERCENT = 1000.0
DNS_AUTO_RECHECK_INTERVAL_SECONDS = 86400.0
DNS_AUTO_RECHECK_PARALLELISM = 1024
DNS_AUTO_RECHECK_JITTER_PERCENT = 50.0
DNS_AUTO_FAILURE_THRESHOLD = 10000
DNS_AUTO_FAILURE_RECHECK_COOLDOWN_SECONDS = 86400.0
`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadClientConfig(writeDNSAutoConfigFile(t, settings))
			if err != nil {
				t.Fatal(err)
			}
			if name == "minimums" {
				assertDNSAutoFields(t, cfg, map[string]any{
					"DNSAutoSwitchConfirmationCount":       0,
					"DNSAutoMinSpeedImprovementPercent":    0.0,
					"DNSAutoRecheckJitterPercent":          0.0,
					"DNSAutoFailureRecheckCooldownSeconds": 0.0,
				})
			}
		})
	}
}

func TestClientConfigDNSAutoCLIOverrides(t *testing.T) {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	binder, err := NewClientConfigFlagBinder(fs)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{
		"-dns-auto-query-types=srv,txt",
		"-dns-auto-probe-count=9",
		"-dns-auto-probe-timeout-seconds=4.5",
		"-dns-auto-min-success-percent=80",
		"-dns-auto-switch-confirmation-count=0",
		"-dns-auto-min-speed-improvement-percent=30",
		"-dns-auto-recheck-enabled=false",
		"-dns-auto-recheck-interval-seconds=1200",
		"-dns-auto-recheck-parallelism=3",
		"-dns-auto-recheck-jitter-percent=0",
		"-dns-auto-failure-recheck-enabled=false",
		"-dns-auto-failure-threshold=7",
		"-dns-auto-failure-recheck-cooldown-seconds=0",
		"-dns-auto-allow-mtu-restart=false",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadClientConfigWithOverrides(writeDNSAutoConfigFile(t, "DNS_AUTO_PROBE_COUNT = 3\n"), binder.Overrides())
	if err != nil {
		t.Fatal(err)
	}
	assertDNSAutoFields(t, cfg, map[string]any{
		"DNSAutoQueryTypes":                    []string{"SRV", "TXT"},
		"DNSAutoProbeCount":                    9,
		"DNSAutoProbeTimeoutSeconds":           4.5,
		"DNSAutoMinSuccessPercent":             80.0,
		"DNSAutoSwitchConfirmationCount":       0,
		"DNSAutoMinSpeedImprovementPercent":    30.0,
		"DNSAutoRecheckEnabled":                false,
		"DNSAutoRecheckIntervalSeconds":        1200.0,
		"DNSAutoRecheckParallelism":            3,
		"DNSAutoRecheckJitterPercent":          0.0,
		"DNSAutoFailureRecheckEnabled":         false,
		"DNSAutoFailureThreshold":              7,
		"DNSAutoFailureRecheckCooldownSeconds": 0.0,
		"DNSAutoAllowMTURestart":               false,
	})
	if len(binder.Overrides().Values) != 14 {
		t.Fatalf("unexpected override count: %d", len(binder.Overrides().Values))
	}
}

func TestClientConfigDNSAutoNormalizesQueryMode(t *testing.T) {
	cfg, err := LoadClientConfig(writeDNSAutoConfigFile(t, "DNS_QUERY_TYPE = \" auto \"\n"))
	if err != nil || cfg.DNSQueryType != "AUTO" {
		t.Fatalf("AUTO must be accepted and normalized, got %q, %v", cfg.DNSQueryType, err)
	}
}

func TestClientConfigDNSAutoValidatesOverrides(t *testing.T) {
	for _, tc := range []struct {
		field string
		value any
		key   string
	}{
		{"DNSAutoQueryTypes", []string{}, "DNS_AUTO_QUERY_TYPES"},
		{"DNSAutoProbeCount", 0, "DNS_AUTO_PROBE_COUNT"},
		{"DNSAutoRecheckIntervalSeconds", 0.0, "DNS_AUTO_RECHECK_INTERVAL_SECONDS"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			_, err := LoadClientConfigWithOverrides(writeDNSAutoConfigFile(t, ""), ClientConfigOverrides{
				Values: map[string]any{tc.field: tc.value},
			})
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("want validation error naming %s, got %v", tc.key, err)
			}
		})
	}
}

func TestClientConfigDNSAutoSampleSettings(t *testing.T) {
	sample, err := os.ReadFile(filepath.Join("..", "..", "client_config.toml.simple"))
	if err != nil {
		t.Fatal(err)
	}
	path := writeDNSAutoConfigFile(t, "")
	if err := os.WriteFile(path, sample, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadClientConfigWithOverrides(path, ClientConfigOverrides{
		Values: map[string]any{"EncryptionKey": "test-key"},
	})
	if err != nil {
		t.Fatalf("sample config should load after setting its shared key: %v", err)
	}
	defaults := reflect.ValueOf(defaultClientConfig())
	actual := reflect.ValueOf(cfg)
	for i := 0; i < defaults.NumField(); i++ {
		field := defaults.Type().Field(i)
		if strings.HasPrefix(field.Tag.Get("toml"), "DNS_AUTO_") {
			if got, want := actual.Field(i).Interface(), defaults.Field(i).Interface(); !reflect.DeepEqual(got, want) {
				t.Errorf("sample %s = %#v, want default %#v", field.Name, got, want)
			}
		}
	}
}
