package adapters

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigBackwardTolerance(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tolerance time.Duration
		refused   bool
	}{
		// Zero tolerance is refused at config load, before a provider can start.
		{"zero", 0, true},
		// The nanosecond immediately below one second is also configuration_invalid.
		{"below-one-second", 999999999, true},
		// One second is accepted with otherwise valid protected configuration.
		{"one-second", 1000000000, false},
		// The provider's existing upper bound still rejects one nanosecond above it.
		{"above-ceiling", 1000000001, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := tempDir(t)
			policyPath := filepath.Join(dir, "policy")
			policy := testTimePolicy()
			policy.BackwardTolerance = tc.tolerance
			raw, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			write(t, policyPath, raw, 0644)
			var config map[string]any
			if err := json.Unmarshal(configBytes(t, dir), &config); err != nil {
				t.Fatal(err)
			}
			config["time_policy"] = policyPath
			raw, err = json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(dir, "config")
			write(t, configPath, raw, 0644)
			write(t, filepath.Join(dir, "allowed"), []byte("public fixture"), 0644)
			loaded, err := loadConfig(configPath, rootFixture)
			if tc.refused {
				wantCode(t, err, configurationInvalid)
				if loaded.TimePolicy != "" || loaded.Repository != "" {
					t.Fatal("refused load returned usable configuration")
				}
			} else if err != nil || loaded.TimePolicy != policyPath {
				t.Fatalf("valid config refused: %v", err)
			}
		})
	}
}
