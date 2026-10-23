// Package conformance_test binds offline fixtures to the existing core APIs.
// Run with go test -v ./internal/conformance. CONFORMANCE_VECTORS may point to
// a scratch copy of vectors/; the specification always comes from this checkout.
// Enrollment registry rows call the public loader with fixture-supplied trust
// and an in-memory CAS store. This harness implements no validation phases or
// admission state machine.
package conformance_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/keys"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/registration"
	"github.com/relux-works/swarma-registrar/internal/sig"
	"github.com/relux-works/swarma-registrar/registry"
)

type vector struct {
	Row, Domain, Mode string
	Input             struct {
		Bytes string `json:"bytes_base64"`
	}
	Fixture struct {
		Audience string
		Registry registryFixture
	}
	Expected struct {
		Code      string
		Canonical string `json:"canonical_bytes_base64"`
		ID        string
		JWT       *struct{ Claims struct{ JTI string } }
		State     struct {
			Authority struct {
				RecordIDs []string `json:"record_ids"`
				Revision  string
			}
		}
	}
}

type registryFixture struct {
	PublisherKey           string   `json:"publisher_key"`
	PreviousPublisherKey   string   `json:"previous_publisher_key"`
	StationHosts           []string `json:"station_hosts"`
	NonstationHosts        []string `json:"nonstation_hosts"`
	Revision               string
	PreviousRevision       string `json:"previous_revision"`
	FirstUse               *bool  `json:"first_use"`
	Available, Approved    bool
	CommitSignatureValid   bool `json:"commit_signature_valid"`
	PinIsExact             bool `json:"pin_is_exact"`
	Descendant             bool
	RollbackStateAvailable bool `json:"rollback_state_available"`
	PersistAvailable       bool `json:"persist_available"`
	Files                  []registryFile
	PreviousFiles          []registryFile `json:"previous_files"`
}

type registryFile struct {
	Path, Kind   string
	PathTemplate string `json:"path_template"`
	Repeat       int
	Bytes        string `json:"bytes_base64"`
}

type pendingCase struct {
	stage, prefix, prefixCode string
}

// Every deferred row is named here. A successful prefix is not a successful
// admission or registry load. R106 deliberately masks an ID mismatch with an
// audit override; its core-prefix expectation is separate from the final code.
var pendingRows = map[string]pendingCase{
	"R136": {"http/media", "registration", "accept"},
	"R137": {"http/media", "registration", "accept"},
	"PR28": {"admission/JWT", "audience", "accept"},
	"PR29": {"admission/JWT", "audience", "accept"},
	"PR30": {"admission/JWT", "audience", "accept"},
	"PR1":  {"admission/JWT-release", "audience", "accept"},
	"PR10": {"admission/JWT-release", "audience", "accept"},
	"PR11": {"admission/JWT-release", "audience", "accept"},
	"PR12": {"admission/JWT-release", "audience", "accept"},
	"PR13": {"admission/JWT-release", "audience", "accept"},
	"PR14": {"admission/JWT-release", "audience", "accept"},
	"PR15": {"admission/JWT-release", "audience", "accept"},
	"PR16": {"admission/JWT-release", "audience", "accept"},
	"PR17": {"admission/JWT-release", "audience", "accept"},
	"PR18": {"admission/JWT-release", "audience", "accept"},
	"PR19": {"admission/JWT-release", "audience", "accept"},
	"PR2":  {"admission/JWT-release", "audience", "accept"},
	"PR20": {"admission/JWT-release", "audience", "accept"},
	"PR21": {"admission/JWT-release", "audience", "accept"},
	"PR22": {"admission/JWT-release", "audience", "accept"},
	"PR23": {"admission/JWT-release", "audience", "accept"},
	"PR24": {"admission/JWT-release", "audience", "accept"},
	"PR25": {"admission/JWT-release", "audience", "accept"},
	"PR26": {"admission/JWT-release", "audience", "accept"},
	"PR27": {"admission/JWT-release", "audience", "accept"},
	"PR3":  {"admission/JWT-release", "audience", "accept"},
	"PR4":  {"admission/JWT-release", "audience", "accept"},
	"PR5":  {"admission/JWT-release", "audience", "accept"},
	"PR6":  {"admission/JWT-release", "audience", "accept"},
	"PR7":  {"admission/JWT-release", "audience", "accept"},
	"PR8":  {"admission/JWT-release", "audience", "accept"},
	"PR9":  {"admission/JWT-release", "audience", "accept"},
	"R103": {"admission/key-window", "registration", "accept"},
	"R105": {"admission/limiter", "audience", "accept"},
	"R106": {"admission/audit-override", "registration", "registration_id_mismatch"},
	"R110": {"admission/key-window", "registration", "accept"},
	"R111": {"admission/limiter", "audience", "accept"},
	"R114": {"http/media", "none", "accept"},
	"R122": {"admission/expiry", "audience", "accept"},
	"R123": {"admission/final-authority", "audience", "accept"},
	"R124": {"admission/clock-fence", "audience", "accept"},
	"R125": {"admission/clock-fence", "audience", "accept"},
	"R126": {"admission/future-time", "audience", "accept"},
	"R127": {"admission/clock-fence", "audience", "accept"},
	"R128": {"admission/signing-generation", "audience", "accept"},
	"R129": {"admission/limiter", "audience", "accept"},
	"R130": {"admission/clock-fence", "audience", "accept"},
	"R131": {"admission/clock-fence", "audience", "accept"},
	"R132": {"admission/clock-fence", "audience", "accept"},
	"R133": {"admission/clock-fence", "audience", "accept"},
	"R62":  {"registry/current-key", "registration", "accept"},
	"R63":  {"registry/current-key", "registration", "accept"},
	"R64":  {"admission/key-window", "registration", "accept"},
	"R65":  {"admission/key-window", "registration", "accept"},
	"R66":  {"admission/key-window", "registration", "accept"},
	"R67":  {"admission/revocation", "registration", "accept"},
	"R73":  {"admission/name-permission", "name", "accept"},
	"R74":  {"admission/name-permission", "name", "accept"},
	"R75":  {"admission/name-permission", "name", "accept"},
	"R78":  {"admission/clock-fence", "audience", "accept"},
	"R79":  {"admission/clock-fence", "audience", "accept"},
	"R80":  {"admission/clock-fence", "audience", "accept"},
	"R81":  {"admission/future-time", "audience", "accept"},
	"R82":  {"admission/expiry", "audience", "accept"},
	"R83":  {"admission/nonce", "audience", "accept"},
	"R84":  {"admission/nonce", "audience", "accept"},
	"R85":  {"admission/nonce", "audience", "accept"},
	"R86":  {"admission/limiter", "audience", "accept"},
	"R87":  {"admission/limiter", "audience", "accept"},
	"R88":  {"admission/limiter", "audience", "accept"},
	"R90":  {"http/media", "none", "accept"},
	"R91":  {"http/media", "none", "accept"},
	"R92":  {"http/endpoint", "none", "accept"},
	"R93":  {"http/method", "none", "accept"},
	"R94":  {"registry/availability", "registration", "accept"},
	"R95":  {"admission/signer", "audience", "accept"},
	"R96":  {"admission/audit", "audience", "accept"},
	"R97":  {"admission/audit", "audience", "accept"},
	"R98":  {"admission/final-authority", "audience", "accept"},
	"R99":  {"admission/nonce", "audience", "accept"},
}

// Executed routes are fixed by row identity, never selected from expected.code.
var executedRows = map[string]string{
	"E100": "registry-bootstrap",
	"E101": "registry-bootstrap",
	"E102": "registry-bootstrap",
	"E103": "registry-bootstrap",
	"E104": "registry-reload",
	"E105": "registry-bootstrap",
	"E106": "registry-bootstrap",
	"E107": "registry-bootstrap",
	"E108": "registry-bootstrap",
	"E109": "registry-bootstrap",
	"E110": "registry-reload",
	"E111": "registry-bootstrap",
	"E12":  "registry-bootstrap",
	"E14":  "registry-bootstrap",
	"E16":  "registry-bootstrap",
	"E25":  "registry-bootstrap",
	"E26":  "registry-bootstrap",
	"E27":  "registry-bootstrap",
	"E28":  "registry-bootstrap",
	"E29":  "registry-bootstrap",
	"E30":  "registry-bootstrap",
	"E31":  "registry-bootstrap",
	"E36":  "registry-bootstrap",
	"E37":  "registry-bootstrap",
	"E38":  "registry-bootstrap",
	"E39":  "registry-bootstrap",
	"E40":  "registry-bootstrap",
	"E41":  "registry-bootstrap",
	"E42":  "registry-bootstrap",
	"E43":  "registry-bootstrap",
	"E45":  "registry-bootstrap",
	"E46":  "registry-bootstrap",
	"E47":  "registry-bootstrap",
	"E48":  "registry-bootstrap",
	"E49":  "registry-bootstrap",
	"E50":  "registry-bootstrap",
	"E51":  "registry-bootstrap",
	"E52":  "registry-bootstrap",
	"E53":  "registry-bootstrap",
	"E54":  "registry-bootstrap",
	"E55":  "registry-bootstrap",
	"E56":  "registry-bootstrap",
	"E57":  "registry-bootstrap",
	"E58":  "registry-bootstrap",
	"E59":  "registry-bootstrap",
	"E60":  "registry-bootstrap",
	"E61":  "registry-bootstrap",
	"E62":  "registry-bootstrap",
	"E63":  "registry-bootstrap",
	"E64":  "registry-bootstrap",
	"E65":  "registry-bootstrap",
	"E66":  "registry-bootstrap",
	"E67":  "registry-bootstrap",
	"E68":  "registry-bootstrap",
	"E69":  "registry-bootstrap",
	"E70":  "registry-bootstrap",
	"E71":  "registry-bootstrap",
	"E72":  "registry-bootstrap",
	"E73":  "registry-bootstrap",
	"E74":  "registry-reload",
	"E75":  "registry-reload",
	"E76":  "registry-reload",
	"E77":  "registry-reload",
	"E78":  "registry-bootstrap",
	"E79":  "registry-bootstrap",
	"E80":  "registry-bootstrap",
	"E81":  "registry-reload",
	"E83":  "registry-bootstrap",
	"E84":  "registry-bootstrap",
	"E85":  "registry-bootstrap",
	"E86":  "registry-bootstrap",
	"E88":  "registry-bootstrap",
	"E89":  "registry-bootstrap",
	"E90":  "registry-bootstrap",
	"E91":  "registry-bootstrap",
	"E92":  "registry-bootstrap",
	"E93":  "registry-bootstrap",
	"E94":  "registry-bootstrap",
	"E95":  "registry-bootstrap",
	"E96":  "registry-bootstrap",
	"E97":  "registry-bootstrap",
	"E98":  "registry-bootstrap",
	"E99":  "registry-bootstrap",
	"PE1":  "registry-bootstrap",
	"PE10": "registry-bootstrap",
	"PE11": "registry-bootstrap",
	"PE12": "registry-bootstrap",
	"PE13": "registry-bootstrap",
	"PE2":  "registry-bootstrap",
	"PE3":  "registry-bootstrap",
	"PE4":  "registry-bootstrap",
	"PE5":  "registry-bootstrap",
	"PE6":  "registry-reload",
	"PE7":  "registry-bootstrap",
	"PE8":  "registry-bootstrap",
	"PE9":  "registry-reload",

	"R134": "name",
	"R135": "name",
	"E112": "registry-bootstrap",
	"E113": "registry-bootstrap",
	"E114": "registry-bootstrap",
	"PE14": "registry-bootstrap",
	"PE15": "registry-bootstrap",
	"E01":  "envelope",
	"E02":  "envelope",
	"E03":  "envelope",
	"E04":  "envelope",
	"E05":  "envelope",
	"E06":  "envelope",
	"E07":  "envelope",
	"E08":  "envelope",
	"E09":  "envelope",
	"E10":  "envelope",
	"E11":  "envelope",
	"E13":  "envelope",
	"E15":  "envelope",
	"E17":  "envelope",
	"E18":  "envelope",
	"E19":  "envelope",
	"E20":  "envelope",
	"E21":  "envelope",
	"E22":  "envelope",
	"E23":  "envelope",
	"E24":  "envelope",
	"E32":  "enrollment-id",
	"E33":  "enrollment-signature",
	"E34":  "enrollment-signature",
	"E35":  "enrollment-signature",
	"E44":  "enrollment-key",
	"E82":  "envelope",
	"E87":  "enrollment-signature",
	"PC1":  "codec",
	"PC10": "extract",
	"PC2":  "codec",
	"PC3":  "codec",
	"PC4":  "codec",
	"PC5":  "codec",
	"PC6":  "codec",
	"PC7":  "codec",
	"PC8":  "codec",
	"PC9":  "codec",
	"R01":  "registration",
	"R02":  "registration",
	"R03":  "registration",
	"R04":  "registration",
	"R05":  "registration",
	"R06":  "registration",
	"R07":  "registration",
	"R08":  "registration",
	"R09":  "registration",
	"R10":  "registration",
	"R100": "registration",
	"R101": "registration",
	"R102": "registration",
	"R104": "name",
	"R107": "registration",
	"R108": "registration",
	"R109": "registration",
	"R11":  "registration",
	"R112": "registration",
	"R115": "registration",
	"R116": "registration",
	"R117": "registration",
	"R118": "registration",
	"R119": "registration",
	"R12":  "registration",
	"R120": "registration",
	"R121": "registration",
	"R13":  "registration",
	"R14":  "registration",
	"R15":  "registration",
	"R16":  "registration",
	"R17":  "registration",
	"R18":  "registration",
	"R19":  "registration",
	"R20":  "registration",
	"R21":  "registration",
	"R22":  "registration",
	"R23":  "registration",
	"R24":  "registration",
	"R25":  "registration",
	"R26":  "registration",
	"R27":  "registration",
	"R28":  "registration",
	"R29":  "registration",
	"R30":  "registration",
	"R31":  "registration",
	"R32":  "registration",
	"R33":  "registration",
	"R34":  "registration",
	"R35":  "registration",
	"R36":  "registration",
	"R37":  "registration",
	"R38":  "registration",
	"R39":  "registration",
	"R40":  "registration",
	"R41":  "registration",
	"R42":  "registration",
	"R43":  "registration",
	"R44":  "registration",
	"R45":  "registration",
	"R46":  "registration",
	"R47":  "registration",
	"R48":  "registration",
	"R49":  "registration",
	"R50":  "registration",
	"R51":  "registration",
	"R52":  "registration",
	"R53":  "registration",
	"R54":  "registration",
	"R55":  "registration",
	"R56":  "registration",
	"R57":  "registration",
	"R58":  "registration",
	"R59":  "registration",
	"R60":  "registration",
	"R61":  "registration",
	"R68":  "name",
	"R69":  "name",
	"R70":  "name",
	"R71":  "name",
	"R72":  "name",
	"R76":  "audience",
	"R77":  "audience",
	"R89":  "registration",
}

type specRow struct {
	line            int
	domain, outcome string
}
type counts struct{ pass, fail, pending, prefixes int }
type observation struct {
	err                      error
	canonical                []byte
	envelope                 *envelope.Envelope
	proof                    *registration.Body
	snapshot                 *registry.Snapshot
	water                    *registry.HighWater
	persisted                *registry.HighWater
	commits                  int
	setupErr                 error
	before                   *registry.HighWater
	retained, retainedBefore *registry.HighWater
	previous                 *registry.Snapshot
}

// Every planned row is classified exactly once. Executable rows must match the
// stored outcome and stated canonical bytes/ID. Deferred rows check only their
// available prefix; no clock, authority, nonce, limiter, audit or JWT is proved.
func TestVectorConformance(t *testing.T) {
	// go test runs each package in its source directory; runtime.Caller paths
	// may be module-relative under -trimpath and cannot locate fixture files.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(cwd, "..", ".."))
	vectorRoot := os.Getenv("CONFORMANCE_VECTORS")
	if vectorRoot == "" {
		vectorRoot = filepath.Join(root, "vectors")
	}
	specification := readSpec(t, filepath.Join(root, "spec", "registrar.md"))
	seen := make(map[string]bool)
	totals := map[string]*counts{"registration/1": {}, "enrollment/1": {}}
	for _, domainDir := range []string{"registration-1", "enrollment-1"} {
		domain := strings.Replace(domainDir, "-1", "/1", 1)
		files := vectorFiles(t, filepath.Join(vectorRoot, domainDir))
		for _, file := range files {
			var v vector
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatalf("%s: fixture JSON: %v", filepath.Base(file), err)
			}
			if v.Row == "" || filepath.Base(file) != v.Row+".json" || v.Domain != domain || v.Expected.Code == "" {
				t.Fatalf("%s: inconsistent row/domain/outcome metadata", filepath.Base(file))
			}
			if seen[v.Row] {
				t.Fatalf("%s: duplicate vector", v.Row)
			}
			seen[v.Row] = true
			spec, ok := specification[v.Row]
			if !ok || spec.domain != domain {
				t.Fatalf("%s: not in the two-domain specification plan", v.Row)
			}
			route, executed := executedRows[v.Row]
			pending, deferred := pendingRows[v.Row]
			if executed == deferred {
				t.Fatalf("%s: unclassified or multiply classified row", v.Row)
			}
			stat := totals[domain]
			passed := t.Run(domainDir+"/"+v.Row, func(t *testing.T) {
				input, err := base64.RawURLEncoding.Strict().DecodeString(v.Input.Bytes)
				if err != nil || base64.RawURLEncoding.EncodeToString(input) != v.Input.Bytes {
					t.Fatal("fixture input.bytes_base64 is not canonical base64url")
				}
				want := v.Expected.Code
				if deferred {
					t.Logf("stage-pending %s: %s; final expectation=%s; spec/registrar.md:%d", v.Row, pending.stage, want, spec.line)
					route, want = pending.prefix, pending.prefixCode
					if route == "none" {
						return
					}
				}
				got := exercise(v, input, route)
				code := resultCode(got.err)
				if code != want {
					t.Errorf("DISAGREEMENT %s spec/registrar.md:%d (plan=%s): route=%s core=%s vector=%s prefix-expectation=%s", v.Row, spec.line, spec.outcome, route, code, v.Expected.Code, want)
				}
				if strings.HasPrefix(route, "registry-") {
					assertRegistryObservation(t, v, got)
				}
				if v.Expected.Canonical != "" && !bytes.Equal(got.canonical, decodeExpected(t, v.Expected.Canonical)) {
					t.Errorf("DISAGREEMENT %s spec/registrar.md:%d: core canonical bytes differ from vector", v.Row, spec.line)
				}
				if got.envelope != nil && v.Expected.ID != "" && got.envelope.ID != v.Expected.ID {
					t.Errorf("DISAGREEMENT %s spec/registrar.md:%d: core id=%s vector id=%s", v.Row, spec.line, got.envelope.ID, v.Expected.ID)
				}
				// The JWT claim is only an independent stated proof-ID witness;
				// this assertion does not issue or validate the JWT itself.
				if got.proof != nil && v.Expected.JWT != nil && got.proof.ID != v.Expected.JWT.Claims.JTI {
					t.Errorf("DISAGREEMENT %s spec/registrar.md:%d: core id=%s vector JWT jti=%s", v.Row, spec.line, got.proof.ID, v.Expected.JWT.Claims.JTI)
				}
			})
			switch {
			case !passed:
				stat.fail++
			case deferred:
				stat.pending++
				if pending.prefix != "none" {
					stat.prefixes++
				}
			default:
				stat.pass++
			}
		}
	}
	for row := range specification {
		if !seen[row] {
			t.Errorf("%s: planned vector missing", row)
		}
	}
	for row := range executedRows {
		if !seen[row] {
			t.Errorf("%s: stale executed classification", row)
		}
	}
	for row := range pendingRows {
		if !seen[row] {
			t.Errorf("%s: stale stage-pending classification", row)
		}
	}
	for _, domain := range []string{"registration/1", "enrollment/1"} {
		c := totals[domain]
		t.Logf("COUNTS %s: executed-pass=%d executed-fail=%d stage-pending=%d (available prefixes verified=%d)", domain, c.pass, c.fail, c.pending, c.prefixes)
	}
}

func exercise(v vector, raw []byte, route string) observation {
	switch route {
	case "registry-bootstrap", "registry-reload":
		return exerciseRegistry(v, raw, route == "registry-bootstrap")
	case "codec", "extract":
		value, err := ccj.Parse(raw, refusal.EnrollmentMalformed)
		if err != nil {
			return observation{err: err}
		}
		if route == "extract" {
			obj, ok := value.(map[string]any)
			if !ok {
				return observation{err: fmt.Errorf("extraction fixture must be an object")}
			}
			value, ok = obj["body"]
			if !ok {
				return observation{err: fmt.Errorf("extraction fixture lacks body")}
			}
		}
		canonical, err := ccj.Marshal(value, refusal.EnrollmentMalformed)
		return observation{err: err, canonical: canonical}
	case "registration", "name", "audience":
		b, err := registration.Read(bytes.NewReader(raw))
		out := observation{err: err, proof: b}
		if err != nil {
			return out
		}
		e, err := envelope.Parse(raw, envelope.Registration)
		if err != nil {
			out.err = err
			return out
		}
		out.envelope, out.canonical = e, e.CanonicalBody
		if route != "registration" {
			out.err = b.CheckName(v.Fixture.Audience)
		}
		if out.err == nil && route == "audience" {
			out.err = b.CheckAudience(v.Fixture.Audience)
		}
		return out
	case "envelope", "enrollment-key", "enrollment-id", "enrollment-signature", "enrollment-positive":
		e, err := envelope.Read(bytes.NewReader(raw), envelope.Enrollment)
		out := observation{err: err, envelope: e}
		if err != nil {
			return out
		}
		out.canonical = e.CanonicalBody
		if route == "envelope" {
			return out
		}
		// Keep the reviewed legacy prefix routes. Registry rows above call
		// the public loader rather than duplicate its schema/phases.
		out.err = enrollmentKeys(e.Body)
		if out.err != nil || route == "enrollment-key" {
			return out
		}
		out.err = e.CheckID()
		if out.err != nil || route == "enrollment-id" {
			return out
		}
		publisher, err := keys.ParseEnrollment(v.Fixture.Registry.PublisherKey)
		if err != nil {
			out.err = err
			return out
		}
		out.err = sig.Verify(publisher, e.Preimage, e.Signature, envelope.Enrollment)
		return out
	default:
		return observation{err: fmt.Errorf("unknown core route %q", route)}
	}
}

func enrollmentKeys(body map[string]any) error {
	entries, ok := body["keys"].([]any)
	if !ok {
		return fmt.Errorf("key adapter needs keys array; enrollment schema is pending")
	}
	for _, entry := range entries {
		obj, ok := entry.(map[string]any)
		if !ok {
			return fmt.Errorf("key adapter needs object entry")
		}
		text, ok := obj["key"].(string)
		if !ok {
			return fmt.Errorf("key adapter needs key string")
		}
		if _, err := keys.ParseEnrollment(text); err != nil {
			return err
		}
	}
	return nil
}

func resultCode(err error) string {
	if err == nil {
		return "accept"
	}
	var typed *refusal.Error
	if errors.As(err, &typed) {
		return string(typed.Code)
	}
	return "unexpected-error: " + err.Error()
}

func decodeExpected(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != text {
		t.Fatal("invalid expected byte encoding")
	}
	return raw
}

func vectorFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 || filepath.Ext(path) != ".json" {
			return fmt.Errorf("unexpected vector entry %s", filepath.Base(path))
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return files
}

func readSpec(t *testing.T, path string) map[string]specRow {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rows := make(map[string]specRow)
	inTable := false
	for i, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "## Appendix B.") {
			inTable = true
			continue
		}
		if strings.HasPrefix(line, "### B.1") {
			break
		}
		if !inTable || !strings.HasPrefix(line, "| ") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) != 8 {
			continue
		}
		id, domain := strings.TrimSpace(cells[1]), strings.TrimSpace(cells[2])
		if domain != "registration/1" && domain != "enrollment/1" {
			continue
		}
		if _, exists := rows[id]; exists {
			t.Fatalf("duplicate planned row %s", id)
		}
		rows[id] = specRow{line: i + 1, domain: domain, outcome: strings.TrimSpace(cells[5])}
	}
	if len(rows) == 0 {
		t.Fatal("no Appendix B two-domain rows found")
	}
	return rows
}
