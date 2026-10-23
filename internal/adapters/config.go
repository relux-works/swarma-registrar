package adapters

import (
	"net/netip"
	"os"
	"strings"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-registrar/enrollment"
	internalEnrollment "github.com/relux-works/swarma-registrar/internal/enrollment"
)

// Config is immutable startup configuration. Paths are absolute; no environment
// expansion, branch following, remote sink or healthy-clock switch is supported.
type Config struct {
	Audience, Repository, Revision, AllowedSigners, PublisherKey string
	HighWater, SigningKey, AuditFile                             string
	Stations                                                     map[string]bool
	PerKey, PerName                                              int
}

func LoadConfig(path string) (Config, error) { return loadConfig(path, protected) }
func loadConfig(path string, guard func(os.FileInfo, int) bool) (Config, error) {
	raw, err := readProtectedWith(path, 65536, guard)
	if err != nil {
		return Config{}, err
	}
	c, err := ParseConfig(raw)
	if err != nil {
		return Config{}, err
	}
	if _, err = readProtectedWith(c.AllowedSigners, 65536, guard); err != nil {
		return Config{}, failure(configurationInvalid)
	}
	return c, nil
}

// ParseConfig validates bytes only; it does not attest file ownership or pin
// provenance. Production callers use LoadConfig for both checks at startup.
func ParseConfig(raw []byte) (Config, error) {
	bad := func() (Config, error) { return Config{}, failure(configurationInvalid) }
	if len(raw) > 65536 {
		return bad()
	}
	value, err := ccj.Parse(raw, configurationInvalid)
	if err != nil {
		return bad()
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return bad()
	}
	required := []string{"v", "audience", "repository", "revision", "allowed_signers", "publisher_key", "stations", "high_water", "signing_key", "audit_file"}
	if len(obj) < len(required) || len(obj) > len(required)+2 {
		return bad()
	}
	allowed := map[string]bool{"per_key": true, "per_name": true}
	for _, name := range required {
		if _, ok := obj[name]; !ok {
			return bad()
		}
		allowed[name] = true
	}
	for name := range obj {
		if !allowed[name] {
			return bad()
		}
	}
	if obj["v"] != int64(1) {
		return bad()
	}
	str := func(name string) string { s, _ := obj[name].(string); return s }
	c := Config{Audience: str("audience"), Repository: str("repository"), Revision: str("revision"), AllowedSigners: str("allowed_signers"), PublisherKey: str("publisher_key"), HighWater: str("high_water"), SigningKey: str("signing_key"), AuditFile: str("audit_file"), Stations: map[string]bool{}, PerKey: 10, PerName: 3}
	for _, path := range []string{c.Repository, c.AllowedSigners, c.HighWater, c.SigningKey, c.AuditFile} {
		if !absolute(path) {
			return bad()
		}
	}
	if !fullRevision(c.Revision) || !serverName(c.Audience) {
		return bad()
	}
	hosts, ok := obj["stations"].(map[string]any)
	if !ok {
		return bad()
	}
	for host, value := range hosts {
		station, ok := value.(bool)
		if !ok || !internalEnrollment.ValidHost(host) {
			return bad()
		}
		c.Stations[host] = station
	}
	if _, err := enrollment.NewPolicy(c.Audience, c.PublisherKey, c.Stations); err != nil {
		return bad()
	}
	for _, limit := range []struct {
		name   string
		target *int
		max    int64
	}{{"per_key", &c.PerKey, 10}, {"per_name", &c.PerName, 3}} {
		if v, present := obj[limit.name]; present {
			n, ok := v.(int64)
			if !ok || n < 1 || n > limit.max {
				return bad()
			}
			*limit.target = int(n)
		}
	}
	return c, nil
}

// serverName checks the Matrix server-name grammar without DNS or rewriting the
// configured spelling: https://spec.matrix.org/v1.17/appendices/#server-name .
func serverName(value string) bool {
	if len(value) == 0 || len(value) > 255 {
		return false
	}
	host, port := value, ""
	hasPort := false
	if strings.HasPrefix(value, "[") {
		end := strings.IndexByte(value, ']')
		if end < 0 {
			return false
		}
		host = value[1:end]
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return false
		}
		tail := value[end+1:]
		if tail != "" {
			if !strings.HasPrefix(tail, ":") {
				return false
			}
			hasPort = true
			port = tail[1:]
		}
	} else {
		if strings.Count(value, ":") > 1 {
			return false
		}
		if colon := strings.IndexByte(value, ':'); colon >= 0 {
			hasPort = true
			host = value[:colon]
			port = value[colon+1:]
		}
		if len(host) == 0 {
			return false
		}
		for _, c := range host {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
				return false
			}
		}
	}
	if hasPort {
		if len(port) < 1 || len(port) > 5 {
			return false
		}
		for _, c := range port {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
