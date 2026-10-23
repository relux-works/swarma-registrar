// Package enrollment validates enrollment documents without loading registry files.
package enrollment

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/keys"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/registration"
	"github.com/relux-works/swarma-registrar/internal/sig"
)

// Policy contains trusted deployment inputs, copied on construction. Audience
// must already be validated as the deployment's canonical Matrix server name.
// Root ownership, pin provenance and Git trust are the registry adapter's job.
type Policy struct {
	audience  string
	publisher *keys.Key
	stations  map[string]bool
}

func NewPolicy(audience, publisher string, stations map[string]bool) (*Policy, error) {
	if len(audience) < 1 || len(audience) > 255 {
		return nil, refusal.New(refusal.RegistryUnavailable)
	}
	for _, b := range []byte(audience) {
		if b > 127 {
			return nil, refusal.New(refusal.RegistryUnavailable)
		}
	}
	k, err := keys.ParseEnrollment(publisher)
	if err != nil || k.Algorithm() != keys.Ed25519 {
		return nil, refusal.New(refusal.RegistryUnavailable)
	}
	hosts := make(map[string]bool, len(stations))
	for host, station := range stations {
		hosts[host] = station
	}
	return &Policy{audience: audience, publisher: k, stations: hosts}, nil
}
func (p *Policy) Audience() string { return p.audience }

// clone captures a document's policy independently of later caller assignments.
func (p *Policy) clone() *Policy {
	out := *p
	out.publisher = p.publisher.Clone()
	out.stations = make(map[string]bool, len(p.stations))
	for host, station := range p.stations {
		out.stations[host] = station
	}
	return &out
}

// Window is half-open; both instants must lie in this exact key interval.
type Window struct {
	Key                 *keys.Key
	NotBefore, NotAfter int64
}

func (w Window) ValidAt(issuedAt, now int64) bool {
	return issuedAt >= w.NotBefore && issuedAt < w.NotAfter && now >= w.NotBefore && now < w.NotAfter
}

type UIDEntry struct {
	UID   uint32
	Names []string
	Exe   *string
}

// Record represents one verified document, not a current registry or permission
// to issue a credential. Registry snapshots keep private copies of these values.
type Record struct {
	ID, Host      string
	Seq           int64
	Revoked       bool
	Keys          []Window
	Prefix        string
	Explicit      []string
	UIDMap        []UIDEntry
	CanonicalBody []byte
}

func (r *Record) Clone() *Record {
	if r == nil {
		return nil
	}
	out := *r
	out.Keys = append([]Window(nil), r.Keys...)
	for i := range out.Keys {
		out.Keys[i].Key = r.Keys[i].Key.Clone()
	}
	out.Explicit = append([]string(nil), r.Explicit...)
	out.CanonicalBody = append([]byte(nil), r.CanonicalBody...)
	out.UIDMap = make([]UIDEntry, len(r.UIDMap))
	for i, u := range r.UIDMap {
		out.UIDMap[i] = u
		out.UIDMap[i].Names = append([]string(nil), u.Names...)
		if u.Exe != nil {
			exe := *u.Exe
			out.UIDMap[i].Exe = &exe
		}
	}
	return &out
}

// Permits implements only name syntax/ownership; callers check currentness and
// host revocation first. A structured name can never be borrowed via explicit.
func (r *Record) Permits(name, audience string) error {
	if err := (&registration.Body{Name: name}).CheckName(audience); err != nil {
		return err
	}
	if host, structured := registration.StructuredHost(name); structured {
		if host == r.Host && r.Prefix == host+"_" {
			return nil
		}
		return refusal.New(refusal.NameNotPermitted)
	}
	for _, allowed := range r.Explicit {
		if name == allowed {
			return nil
		}
	}
	return refusal.New(refusal.NameNotPermitted)
}

// Document exposes individual phases for snapshot-wide validation. Decode does
// phase 1 only and captures its own policy copy; no record is released until
// schema, id and publisher all verify.
type Document struct {
	policy   *Policy
	envelope *envelope.Envelope
	record   *Record
}

func (p *Policy) Decode(raw []byte) (*Document, error) {
	if p == nil {
		return nil, refusal.New(refusal.RegistryUnavailable)
	}
	e, err := envelope.Parse(raw, envelope.Enrollment)
	if err != nil {
		return nil, err
	}
	return &Document{policy: p.clone(), envelope: e}, nil
}
func (d *Document) CheckReserved() error {
	if _, present := d.envelope.Body["sigs"]; present {
		return refusal.New(refusal.EnrollmentSigsUnsupported)
	}
	return nil
}
func (d *Document) CheckBody() error {
	d.record = nil
	if err := d.CheckReserved(); err != nil {
		return err
	}
	r, err := d.policy.parseBody(d.envelope.Body)
	if err != nil {
		return err
	}
	r.ID = d.envelope.ID
	r.CanonicalBody = append([]byte(nil), d.envelope.CanonicalBody...)
	d.record = r
	return nil
}
func (d *Document) CheckID() error { return d.envelope.CheckID() }
func (d *Document) Verify() (*Record, error) {
	if d.record == nil {
		return nil, refusal.New(refusal.EnrollmentMalformed)
	}
	if err := d.CheckID(); err != nil {
		return nil, err
	}
	if err := sig.Verify(d.policy.publisher, d.envelope.Preimage, d.envelope.Signature, envelope.Enrollment); err != nil {
		return nil, err
	}
	return d.record.Clone(), nil
}
func (p *Policy) Parse(raw []byte) (*Record, error) {
	d, err := p.Decode(raw)
	if err != nil {
		return nil, err
	}
	if err = d.CheckReserved(); err != nil {
		return nil, err
	}
	if err = d.CheckBody(); err != nil {
		return nil, err
	}
	return d.Verify()
}

var hostPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

func ValidHost(host string) bool { return hostPattern.MatchString(host) }
func shape(obj map[string]any, required []string, optional ...string) bool {
	if len(obj) < len(required) || len(obj) > len(required)+len(optional) {
		return false
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, name := range required {
		allowed[name] = true
		if _, ok := obj[name]; !ok {
			return false
		}
	}
	for _, name := range optional {
		allowed[name] = true
	}
	for name := range obj {
		if !allowed[name] {
			return false
		}
	}
	return true
}
func (p *Policy) parseBody(b map[string]any) (*Record, error) {
	fail := func() (*Record, error) { return nil, refusal.New(refusal.EnrollmentMalformed) }
	if !shape(b, []string{"type", "host", "keys", "names", "seq", "state"}, "uid_map") {
		return fail()
	}
	kind, kindOK := b["type"].(string)
	host, hostOK := b["host"].(string)
	seq, seqOK := b["seq"].(int64)
	state, stateOK := b["state"].(string)
	if !kindOK || kind != "enrollment/1" || !hostOK || !ValidHost(host) || !seqOK || seq < 1 || seq > ccj.MaxInteger || !stateOK || (state != "active" && state != "revoked") {
		return fail()
	}
	station, classified := p.stations[host]
	if !classified {
		return nil, refusal.New(refusal.RegistryUnavailable)
	} // §4.1; Appendix B E90.
	r := &Record{Host: host, Seq: seq, Revoked: state == "revoked"}
	keyArray, ok := b["keys"].([]any)
	if !ok || len(keyArray) < 1 || len(keyArray) > 16 {
		return fail()
	}
	seenKeys := map[string]bool{}
	for _, v := range keyArray {
		k, ok := v.(map[string]any)
		if !ok || !shape(k, []string{"key", "not_before", "not_after"}) {
			return fail()
		}
		text, keyOK := k["key"].(string)
		before, beforeOK := k["not_before"].(string)
		after, afterOK := k["not_after"].(string)
		if !keyOK || !beforeOK || !afterOK {
			return fail()
		}
		public, err := keys.ParseEnrollment(text)
		if err != nil || seenKeys[text] {
			return fail()
		}
		seenKeys[text] = true
		lo, loOK := registration.ParseTimestamp(before)
		hi, hiOK := registration.ParseTimestamp(after)
		if !loOK || !hiOK || lo >= hi {
			return fail()
		}
		r.Keys = append(r.Keys, Window{public, lo, hi})
	}
	names, ok := b["names"].(map[string]any)
	if !ok || !shape(names, []string{"prefix", "explicit"}) {
		return fail()
	}
	prefix, prefixOK := names["prefix"].(string)
	explicit, explicitOK := names["explicit"].([]any)
	if !prefixOK || prefix != host+"_" || !explicitOK || len(explicit) > 256 {
		return fail()
	}
	r.Prefix = prefix
	seenNames := map[string]bool{}
	for _, v := range explicit {
		name, ok := v.(string)
		if !ok || !registration.ValidLegacyName(name, p.audience) || seenNames[name] {
			return fail()
		}
		seenNames[name] = true
		r.Explicit = append(r.Explicit, name)
	}
	uidValue, hasMap := b["uid_map"]
	if !hasMap {
		if station {
			return fail()
		}
		return r, nil
	}
	uidMap, ok := uidValue.([]any)
	if !ok || len(uidMap) < 1 || len(uidMap) > 256 {
		return fail()
	}
	seenUIDs := map[int64]bool{}
	claimedNames := map[string]bool{}
	for _, v := range uidMap {
		row, ok := v.(map[string]any)
		if !ok || !shape(row, []string{"uid", "names"}, "exe") {
			return fail()
		}
		uid, uidOK := row["uid"].(int64)
		names, namesOK := row["names"].([]any)
		if !uidOK || uid < 1 || uid > 4294967294 || seenUIDs[uid] || !namesOK || len(names) < 1 || len(names) > 64 {
			return fail()
		}
		seenUIDs[uid] = true
		out := UIDEntry{UID: uint32(uid)}
		for _, value := range names {
			name, ok := value.(string)
			if !ok || claimedNames[name] || r.Permits(name, p.audience) != nil {
				return fail()
			}
			claimedNames[name] = true
			out.Names = append(out.Names, name)
		}
		if value, present := row["exe"]; present {
			exe, ok := value.(string)
			if !ok || !validExecutable(exe) {
				return fail()
			}
			out.Exe = &exe
		}
		r.UIDMap = append(r.UIDMap, out)
	}
	return r, nil
}
func validExecutable(exe string) bool {
	if len(exe) < 2 || len(exe) > 4096 || !utf8.ValidString(exe) || exe[0] != '/' {
		return false
	}
	for _, b := range []byte(exe) {
		if b < 32 || b == 127 || b == '\\' {
			return false
		}
	}
	for _, component := range strings.Split(exe[1:], "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}
