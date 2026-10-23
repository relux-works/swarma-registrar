// Command vectorgen creates offline contract fixtures from public test material.
// It is not a registrar and never reads deployment configuration or keys.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type M = map[string]any

const epoch int64 = 1893456000

var seeds map[string]string
var host, publisher, jwtKey ed25519.PrivateKey
var pScalar *big.Int
var pPublic string
var derivedKeys = map[string]ed25519.PrivateKey{}
var raw64 = base64.RawURLEncoding

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func hx(s string) []byte  { b, e := hex.DecodeString(s); must(e); return b }
func enc(b []byte) string { return raw64.EncodeToString(b) }
func dec(s string) []byte { b, e := raw64.DecodeString(s); must(e); return b }
func str(v any) string    { return v.(string) }
func num(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case json.Number:
		i, e := n.Int64()
		must(e)
		return i
	case float64:
		return int64(n)
	}
	panic("not integer")
}
func mapv(v any) M { return v.(map[string]any) }
func clone(m M) M {
	b, e := json.Marshal(m)
	must(e)
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v M
	must(d.Decode(&v))
	return v
}
func jsonBytes(v any) []byte {
	b, e := json.MarshalIndent(v, "", "  ")
	must(e)
	return append(b, '\n')
}
func ccj(v any) []byte {
	switch x := v.(type) {
	case nil:
		return []byte("null")
	case bool:
		if x {
			return []byte("true")
		}
		return []byte("false")
	case string:
		var b strings.Builder
		b.WriteByte('"')
		for _, r := range x {
			switch r {
			case '"', '\\':
				b.WriteByte('\\')
				b.WriteRune(r)
			case '\b':
				b.WriteString(`\b`)
			case '\f':
				b.WriteString(`\f`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			default:
				if r < 32 {
					fmt.Fprintf(&b, `\u%04x`, r)
				} else {
					b.WriteRune(r)
				}
			}
		}
		b.WriteByte('"')
		return []byte(b.String())
	case M:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := [][]byte{}
		for _, k := range keys {
			parts = append(parts, append(append(ccj(k), ':'), ccj(x[k])...))
		}
		return append(append([]byte{'{'}, bytes.Join(parts, []byte{','})...), '}')
	case []any:
		parts := [][]byte{}
		for _, v := range x {
			parts = append(parts, ccj(v))
		}
		return append(append([]byte{'['}, bytes.Join(parts, []byte{','})...), ']')
	case []M:
		a := []any{}
		for _, m := range x {
			a = append(a, m)
		}
		return ccj(a)
	case int:
		return []byte(strconv.Itoa(x))
	case int64:
		return []byte(strconv.FormatInt(x, 10))
	case json.Number:
		return []byte(x.String())
	default:
		panic(fmt.Sprintf("unsupported canonical value %T", v))
	}
}
func ts(n int64) string                 { return time.Unix(epoch+n, 0).UTC().Format("2006-01-02T15:04:05Z") }
func edpub(k ed25519.PrivateKey) string { return "ed25519:" + enc(k.Public().(ed25519.PublicKey)) }
func extra(label string) ed25519.PrivateKey {
	b := append(append([]byte{}, host.Seed()...), []byte(label)...)
	h := sha256.Sum256(b)
	key := ed25519.NewKeyFromSeed(h[:])
	derivedKeys[label] = key
	return key
}
func nonce(i byte) string {
	b := make([]byte, 16)
	for n := range b {
		b[n] = i + byte(n)
	}
	return enc(b)
}
func preimage(body M) []byte {
	return append([]byte("swarma-registrar "+str(body["type"])+"\n"), ccj(body)...)
}
func id(body M) string {
	h := sha256.Sum256(preimage(body))
	return "sha256:" + hex.EncodeToString(h[:])
}

// Public test seeds let weak-key witnesses satisfy the ordinary equation;
// rejection must still enforce the explicit subgroup/nonidentity policy.
func fromLittle(b []byte) *big.Int {
	r := append([]byte{}, b...)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return new(big.Int).SetBytes(r)
}
func expandedScalar(key ed25519.PrivateKey) *big.Int {
	h := sha512.Sum512(key.Seed())
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64
	return new(big.Int).Mod(fromLittle(h[:32]), orderL)
}
func weakSignature(body M) []byte {
	public := dec(strings.TrimPrefix(str(body["key"]), "ed25519:"))
	message := preimage(body)
	for i := 0; ; i++ {
		nonceKey := host
		if i > 0 {
			nonceKey = extra(fmt.Sprintf("weak-point-nonce-%d", i))
		}
		r := nonceKey.Public().(ed25519.PublicKey)
		challenge := sha512.Sum512(append(append(append([]byte{}, r...), public...), message...))
		h := new(big.Int).Mod(fromLittle(challenge[:]), orderL)
		if str(body["key"]) != "ed25519:"+enc(append([]byte{1}, make([]byte, 31)...)) && h.Bit(0) != 0 {
			continue
		}
		scalar := expandedScalar(nonceKey)
		if bytes.Equal(public, weak(host.Public().(ed25519.PublicKey))) {
			scalar.Add(scalar, new(big.Int).Mul(h, expandedScalar(host)))
			scalar.Mod(scalar, orderL)
		}
		return append(append([]byte{}, r...), little(scalar)...)
	}
}
func pSign(msg []byte, attempt int) []byte {
	c := elliptic.P256()
	n := c.Params().N
	h := sha256.Sum256(msg)
	material := append(append(append([]byte{}, pScalar.FillBytes(make([]byte, 32))...), h[:]...), []byte(strconv.Itoa(attempt))...)
	kh := sha256.Sum256(material)
	k := new(big.Int).SetBytes(kh[:])
	k.Mod(k, new(big.Int).Sub(n, big.NewInt(1)))
	k.Add(k, big.NewInt(1))
	x, _ := c.ScalarBaseMult(k.Bytes())
	r := new(big.Int).Mod(x, n)
	s := new(big.Int).Mul(r, pScalar)
	s.Add(s, new(big.Int).SetBytes(h[:]))
	s.Mul(s, new(big.Int).ModInverse(k, n))
	s.Mod(s, n)
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		s.Sub(n, s)
	}
	return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
}
func envelope(body M, key ed25519.PrivateKey) M {
	p := preimage(body)
	sig := ed25519.Sign(key, p)
	if body["type"] == "registration/1" && body["key"] == pPublic {
		sig = pSign(p, 0)
	}
	return M{"body": body, "id": id(body), "sig": enc(sig)}
}
func reg() M {
	return M{"type": "registration/1", "key": edpub(host), "name": "host-a_project_dev", "aud": "example.org", "nonce": nonce(0), "iat": ts(60), "exp": ts(180)}
}
func enrollment(label string, key string, seq int) M {
	return M{"type": "enrollment/1", "host": label, "keys": []any{M{"key": key, "not_before": ts(0), "not_after": "2031-01-01T00:00:00Z"}}, "names": M{"prefix": label + "_", "explicit": []any{"legacy.dev"}}, "seq": seq, "state": "active", "uid_map": []any{M{"uid": 1001, "names": []any{label + "_project_dev"}}}}
}
func record(body M) M { return envelope(body, publisher) }
func file(path string, env M) M {
	return M{"path": path, "kind": "regular", "bytes_base64": enc(ccj(env)), "repeat": 1}
}
func registry() M {
	return M{"available": true, "commit_signature_valid": true, "approved": true, "pin_is_exact": true, "revision": strings.Repeat("a", 40), "descendant": true, "rollback_state_available": true, "persist_available": true, "station_hosts": []any{"host-a", "host-b"}, "publisher_key": edpub(publisher), "files": []any{file("enrollments/a.json", record(enrollment("host-a", edpub(host), 1)))}, "previous_files": []any{}}
}
func fixture() M {
	return M{"now": epoch + 60, "monotonic_now": 60, "actual_start_millis": (epoch - 31) * 1000, "start_barrier": epoch, "startup_verified": true, "clock_healthy": true, "clock_fenced": false, "audience": "example.org", "registry": registry(), "nonce_cache": []any{}, "limiter_events": []any{}, "key_capacity": 10, "name_capacity": 3, "audit": M{"local_available": true, "remote_ack": true}, "signer_available": true, "signing_generation": "A", "http": M{"path": "/v1/registration", "method": "POST", "content_type": "application/json", "content_encoding": "identity"}}
}
func setKeys(r M, keys ...string) {
	fs := r["files"].([]any)
	env := parse(dec(str(mapv(fs[0])["bytes_base64"])))
	body := mapv(env["body"])
	a := []any{}
	for _, k := range keys {
		a = append(a, M{"key": k, "not_before": ts(0), "not_after": "2031-01-01T00:00:00Z"})
	}
	body["keys"] = a
	r["files"] = []any{file("enrollments/a.json", record(body))}
}
func parse(b []byte) M {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var m M
	must(d.Decode(&m))
	return m
}
func setBody(r M, fn func(M)) {
	fs := r["files"].([]any)
	body := mapv(parse(dec(str(mapv(fs[0])["bytes_base64"])))["body"])
	fn(body)
	r["files"] = []any{file("enrollments/a.json", record(body))}
}
func weak(mixed []byte) []byte {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	b := append([]byte{}, mixed...)
	sign := b[31] & 128
	b[31] &= 127
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	y := new(big.Int).SetBytes(b)
	y.Sub(p, y)
	out := y.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	out[31] |= sign ^ 128
	return out
}
func little(n *big.Int) []byte {
	b := n.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

var orderL = new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 252), func() *big.Int {
	n, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	return n
}())

type row struct{ ID, Domain, Rule, Boundary, Code, Control string }

func jwt(env M, now int64) M {
	body := mapv(env["body"])
	header := M{"alg": "EdDSA", "typ": "JWT"}
	claims := M{"iss": "swarma-registrar", "aud": []any{str(body["aud"])}, "sub": body["name"], "iat": now, "nbf": now, "exp": now + 120, "jti": env["id"]}
	message := enc(ccj(header)) + "." + enc(ccj(claims))
	sig := enc(ed25519.Sign(jwtKey, []byte(message)))
	return M{"header": header, "claims": claims, "signature": sig, "compact": message + "." + sig}
}
func requestStep(env M, now int64, code string) M {
	m := M{"event": "request", "bytes_base64": enc(ccj(env)), "now": epoch + now, "expected": M{"code": code}}
	if code == "accept" {
		mapv(m["expected"])["jwt"] = jwt(env, epoch+now)
	}
	return m
}
func clockStep(now int64, healthy bool) M {
	return M{"event": "clock", "now": epoch + now, "healthy": healthy}
}
func restartStep(millis, now int64, healthy bool) M {
	return M{"event": "restart", "actual_start_millis": epoch*1000 + millis, "now": epoch + now, "startup_verified": healthy}
}

func registrationCase(r row) M {
	body := reg()
	f := fixture()
	rg := mapv(f["registry"])
	before := []any{}
	after := []any{}
	pCases := map[string]bool{"R38": true, "R39": true, "R40": true, "R41": true, "R42": true, "R43": true, "R44": true, "R45": true, "R46": true, "R47": true, "R48": true, "R49": true, "R102": true, "R109": true, "PR2": true, "PR18": true}
	if pCases[r.ID] {
		body["key"] = pPublic
		setKeys(rg, edpub(host), pPublic)
	}
	cache := func(key string) { f["nonce_cache"] = []any{M{"key": key, "nonce": nonce(0), "expires": epoch + 150}} }
	events := func(count int, sameName bool) {
		a := []any{}
		for i := 0; i < count; i++ {
			name := str(body["name"])
			if !sameName {
				name = fmt.Sprintf("host-a_project_r%d", i)
			}
			a = append(a, M{"at": 1, "key": body["key"], "name": name})
		}
		f["limiter_events"] = a
	}
	setWindow := func(lo, hi int64) {
		setBody(rg, func(b M) {
			ks := b["keys"].([]any)
			for _, k := range ks {
				mapv(k)["not_before"] = ts(lo)
				mapv(k)["not_after"] = ts(hi)
			}
		})
	}
	switch r.ID {
	case "R36":
		body["key"] = "unknown:" + enc(host.Public().(ed25519.PublicKey))
	case "R37":
		body["key"] = str(body["key"]) + "="
	case "R38":
		body["key"] = "p256:" + enc(host.Public().(ed25519.PublicKey))
	case "R39":
		x, y := elliptic.P256().ScalarBaseMult(pScalar.Bytes())
		body["key"] = "p256:" + enc(elliptic.Marshal(elliptic.P256(), x, y))
	case "R40":
		k := dec(strings.TrimPrefix(pPublic, "p256:"))
		k[0] = 4
		body["key"] = "p256:" + enc(k)
	case "R41":
		body["key"] = "p256:" + enc(append([]byte{2}, elliptic.P256().Params().P.FillBytes(make([]byte, 32))...))
	case "R42":
		c := elliptic.P256()
		for x := int64(0); ; x++ {
			raw := append([]byte{2}, big.NewInt(x).FillBytes(make([]byte, 32))...)
			px, _ := elliptic.UnmarshalCompressed(c, raw)
			if px == nil {
				body["key"] = "p256:" + enc(raw)
				break
			}
		}
	case "R51":
		body["key"] = "ed25519:" + enc(append([]byte{1}, make([]byte, 31)...))
	case "R52":
		raw := bytes.Repeat([]byte{255}, 32)
		raw[0] = 236
		raw[31] = 127
		body["key"] = "ed25519:" + enc(raw)
	case "R53":
		body["key"] = "ed25519:" + enc(weak(host.Public().(ed25519.PublicKey)))
	case "R54":
		raw := bytes.Repeat([]byte{255}, 32)
		raw[0] = 238
		raw[31] = 127
		body["key"] = "ed25519:" + enc(raw)
	case "R57":
		body["nonce"] = enc(make([]byte, 15))
	case "R58":
		s := str(body["nonce"])
		last := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", s[len(s)-1])
		body["nonce"] = s[:len(s)-1] + string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[last+1])
	case "R59":
		body["exp"] = ts(181)
	case "R60":
		body["exp"] = body["iat"]
	case "R61":
		body["exp"] = ts(59)
	case "R62":
		setKeys(rg, edpub(extra("unenrolled")))
	case "R63":
		old := enrollment("host-a", edpub(host), 1)
		current := enrollment("host-a", edpub(extra("current")), 2)
		rg["files"] = []any{file("enrollments/a.json", record(old)), file("enrollments/b.json", record(current))}
	case "R64":
		setWindow(61, 240)
	case "R65":
		body["iat"] = ts(120)
		body["exp"] = ts(240)
		setWindow(0, 120)
	case "R66":
		f["now"] = epoch + 120
		setWindow(0, 120)
	case "R67":
		setBody(rg, func(b M) { b["state"] = "revoked" })
	case "R68":
		body["name"] = "Host-a_project_dev"
	case "R69":
		body["name"] = "host-a_project_dév"
	case "R70":
		body["name"] = "host-a_project_@dev"
	case "R71":
		body["name"] = ""
	case "R72":
		body["name"] = strings.Repeat("a", 243)
	case "R73":
		body["name"] = "host-b_project_dev"
	case "R74":
		body["name"] = "host-a_project_dev_extra"
	case "R75":
		body["name"] = "legacy.dew"
	case "R76":
		body["aud"] = "EXAMPLE.ORG"
	case "R77":
		body["aud"] = "https://example.org"
	case "R78":
		f["start_barrier"] = epoch + 61
		f["actual_start_millis"] = (epoch + 30) * 1000
	case "R79":
		f["clock_fenced"] = true
		f["clock_healthy"] = false
	case "R80":
		f["clock_healthy"] = false
	case "R81":
		body["iat"] = ts(91)
		body["exp"] = ts(211)
	case "R82":
		f["now"] = epoch + 210
	case "R83", "R84":
		cache(str(body["key"]))
		if r.ID == "R84" {
			body["name"] = "host-a_project_other"
		}
	case "R86":
		events(10, false)
	case "R87":
		events(3, true)
	case "R88":
		one := clone(body)
		one["nonce"] = nonce(1)
		two := clone(body)
		two["nonce"] = nonce(2)
		before = append(before, requestStep(envelope(one, host), 60, "accept"), requestStep(envelope(two, host), 60, "accept"), requestStep(envelope(one, host), 60, "nonce_replayed"))
		body["nonce"] = nonce(3)
	case "R90":
		mapv(f["http"])["content_type"] = "text/plain"
	case "R91":
		mapv(f["http"])["content_encoding"] = "gzip"
	case "R92":
		mapv(f["http"])["path"] = "/unknown"
	case "R93":
		mapv(f["http"])["method"] = "GET"
	case "R94":
		rg["available"] = false
	case "R95":
		f["signer_available"] = false
	case "R96":
		mapv(f["audit"])["remote_ack"] = false
	case "R97":
		mapv(f["audit"])["local_available"] = false
	case "R98":
		f["final_revoked"] = true
	case "R99":
		f["signer_available"] = false
		before = append(before, requestStep(envelope(body, host), 60, "service_unavailable"), M{"event": "signer", "available": true})
	case "R102":
		setKeys(rg, edpub(host))
	case "R103":
		f["now"] = epoch + 120
		setWindow(0, 120)
		setBody(rg, func(b M) { b["state"] = "revoked" })
	case "R104":
		body["name"] = "BAD"
		body["aud"] = "wrong.example"
	case "R105":
		events(3, true)
		cache(str(body["key"]))
	case "R106":
		mapv(f["audit"])["local_available"] = false
	case "R109":
		body["key"] = "p256:" + enc([]byte{0})
	case "R110":
		f["now"] = epoch + 59
		setWindow(60, 240)
	case "R111":
		events(3, true)
	case "R112":
		body["unexpected"] = "synthetic-token-marker"
	case "R114":
		mapv(f["http"])["content_type"] = "application/json; boundary=unexpected"
	case "R115":
		body["nonce"] = "/" + str(body["nonce"])[1:]
	case "R116":
		body["aud"] = "éxample.org"
	case "R117":
		body["sig"] = "unexpected"
	case "R118":
		body["iat"] = "2030-1-01T00:01:00Z"
	case "R119":
		body["iat"] = "2030-01-01T00:01:00"
	case "R121": // Rebind after signing below.
	case "R122":
		f["final_now"] = epoch + 210
	case "R123":
		f["post_audit_revoked"] = true
	case "R124", "R125", "R127", "R130", "R131", "R132", "PR27":
		body["iat"] = ts(90)
		body["exp"] = ts(210)
		if r.ID == "R125" {
			body["iat"] = ts(91)
			body["exp"] = ts(211)
		}
		oldNow := int64(60)
		if r.ID == "R125" {
			oldNow = 61
		}
		f["actual_start_millis"] = epoch * 1000
		f["start_barrier"] = epoch + 31
		before = append(before, requestStep(envelope(body, host), oldNow, "accept"))
		if r.ID == "R130" || r.ID == "R131" || r.ID == "R132" || r.ID == "PR27" {
			before = append(before, clockStep(31, false), restartStep(31200, 31, false), clockStep(62, true))
			f["now"] = epoch + 62
			if r.ID == "R132" || r.ID == "PR27" {
				before = append(before, restartStep(62200, 93, true))
				f["now"] = epoch + 93
			}
			if r.ID == "R131" || r.ID == "PR27" {
				body["iat"] = ts(93)
				body["exp"] = ts(213)
				body["nonce"] = nonce(4)
				f["now"] = epoch + 93
			}
		} else {
			before = append(before, restartStep(61200, 62, true))
			f["now"] = epoch + 62
			if r.ID == "R127" {
				f["now"] = epoch + 92
			}
		}
	case "R126", "PR22", "PR23", "PR24":
		body["iat"] = ts(92)
		body["exp"] = ts(212)
		f["actual_start_millis"] = epoch*1000 + 61200
		f["start_barrier"] = epoch + 92
		f["now"] = epoch + 62
		if r.ID == "R126" {
			f["now"] = epoch + 61
		}
		if r.ID == "PR23" || r.ID == "PR24" {
			f["now"] = epoch + 92
		}
		if r.ID == "PR24" {
			body["iat"] = ts(93)
			body["exp"] = ts(213)
		}
	case "R128":
		f["post_audit_generation"] = "B"
	case "R129":
		f["key_capacity"] = 1
		f["name_capacity"] = 1
		events(1, true)
	case "R133":
		f["actual_start_millis"] = epoch * 1000
		f["start_barrier"] = epoch + 31
		before = append(before, clockStep(40, false), clockStep(60, true))
	case "PR3": // Baseline lifetime is exactly 120.
	case "PR4", "PR21":
		body["exp"] = ts(61)
	case "PR5":
		setWindow(60, 240)
	case "PR6":
		setWindow(0, 61)
	case "PR7":
		body["name"] = strings.Repeat("a", 242)
		setBody(rg, func(b M) { mapv(b["names"])["explicit"] = []any{body["name"]} })
	case "PR8":
		body["name"] = "legacy.dev"
	case "PR9":
		f["actual_start_millis"] = (epoch + 29) * 1000
		f["start_barrier"] = epoch + 60
	case "PR10":
		body["iat"] = ts(90)
		body["exp"] = ts(210)
	case "PR11":
		f["now"] = epoch + 209
	case "PR13":
		events(9, false)
		f["limiter_events"] = append(f["limiter_events"].([]any), M{"at": 0, "key": body["key"], "name": "host-a_project_old"})
	case "PR14":
		events(2, true)
	case "PR18":
		cache(edpub(host))
	case "PR19":
		body["name"] = "host-a_project_dev-q1"
	case "PR25":
		f["key_capacity"] = 1
		f["name_capacity"] = 1
	}
	env := envelope(body, host)
	n, _ := strconv.Atoi(strings.TrimPrefix(r.ID, "R"))
	raw := ccj(env)
	if n >= 1 && n <= 31 {
		raw = commonDefect(env, n, false)
	}
	switch r.ID {
	case "R32", "R101", "R106":
		env["id"] = "sha256:" + strings.Repeat("0", 64)
		if r.ID == "R101" {
			env["sig"] = enc(make([]byte, 64))
		}
		raw = ccj(env)
	case "R33":
		env["sig"] = enc(ed25519.Sign(host, append([]byte("swarma-registrar enrollment/1\n"), ccj(body)...)))
		raw = ccj(env)
	case "R34":
		env["sig"] = enc(ed25519.Sign(host, ccj(env)))
		raw = ccj(env)
	case "R35":
		env["sig"] = enc(ed25519.Sign(host, append(preimage(body), '\n')))
		raw = ccj(env)
	case "R43", "R44", "R45", "R46", "R47", "R49", "R102":
		sig := dec(str(env["sig"]))
		rn := new(big.Int).SetBytes(sig[:32])
		sn := new(big.Int).SetBytes(sig[32:])
		order := elliptic.P256().Params().N
		switch r.ID {
		case "R43":
			rn.SetInt64(0)
		case "R44":
			rn.Set(order)
		case "R45":
			sn.SetInt64(0)
		case "R46":
			sn.Set(order)
		case "R47", "R102":
			sn.Sub(order, sn)
		case "R49":
			rn.Add(rn, big.NewInt(1))
			rn.Mod(rn, order)
		}
		env["sig"] = enc(append(rn.FillBytes(make([]byte, 32)), sn.FillBytes(make([]byte, 32))...))
		raw = ccj(env)
	case "R48":
		for i := 0; ; i++ {
			sig := pSign(preimage(body), i)
			der, e := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])})
			must(e)
			if len(der) == 70 {
				env["sig"] = enc(der)
				break
			}
		}
		raw = ccj(env)
	case "R51", "R52", "R53":
		env["sig"] = enc(weakSignature(body))
		raw = ccj(env)
	case "R50":
		sig := dec(str(env["sig"]))
		copy(sig[32:], little(orderL))
		env["sig"] = enc(sig)
		raw = ccj(env)
	case "R55":
		sig := dec(str(env["sig"]))
		copy(sig[:32], make([]byte, 32))
		env["sig"] = enc(sig)
		raw = ccj(env)
	case "R56":
		sig := dec(str(env["sig"]))
		sig[32] ^= 1
		env["sig"] = enc(sig)
		raw = ccj(env)
	case "R85":
		before = append(before, requestStep(env, 60, "accept"))
	case "R89":
		raw = append(raw, bytes.Repeat([]byte{' '}, 65537-len(raw))...)
		mapv(f["http"])["content_length_present"] = false
	case "R99": // The failed prefix consumes the exact main nonce.
	case "R100":
		raw = commonDefect(env, 1, false)
		raw = bytes.Replace(raw, []byte(str(env["id"])), []byte("sha256:"+strings.Repeat("0", 64)), 1)
	case "R107":
		sig := dec(str(env["sig"]))
		p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(18))
		copy(sig[:32], little(p))
		env["sig"] = enc(sig)
		raw = ccj(env)
	case "R108":
		sig := dec(str(env["sig"]))
		copy(sig[:32], weak(sig[:32]))
		env["sig"] = enc(sig)
		raw = ccj(env)
	case "R120":
		env["sig"] = enc(make([]byte, 65))
		raw = ccj(env)
	case "R121":
		body["name"] = "host-a_project_other"
		env["id"] = id(body)
		raw = ccj(env)
	case "PR12":
		after = append(after, requestStep(env, 60, "nonce_replayed"))
	case "PR15":
		raw = append(raw, bytes.Repeat([]byte{' '}, 65536-len(raw))...)
	case "PR20":
		raw = append([]byte(" \n"), raw...)
		raw = bytes.ReplaceAll(raw, []byte(`"host-a_project_dev"`), []byte(`"\u0068ost-a_project_dev"`))
	}
	return M{"row": r.ID, "domain": r.Domain, "claim": r.Rule + ": " + r.Boundary, "positive_control": r.Control, "mode": "admission", "input": M{"bytes_base64": enc(raw)}, "fixture": f, "before": before, "after": after, "expected": M{"code": r.Code}}
}

// Each malformed fixture pins one concrete witness; no parser result is guessed.
func commonDefect(env M, n int, enroll bool) []byte {
	e := clone(env)
	body := mapv(e["body"])
	codeType := "registration/1"
	if enroll {
		codeType = "enrollment/1"
	}
	raw := ccj(e)
	switch n {
	case 1:
		return bytes.Replace(raw, []byte(`"type":`), []byte(`"type":"`+codeType+`","type":`), 1)
	case 2:
		return bytes.Replace(raw, []byte(`"type":`), []byte(`"\u0074ype":"`+codeType+`","type":`), 1)
	case 3:
		return append([]byte{255}, raw...)
	case 4:
		return bytes.Replace(raw, []byte(`"type":"`+codeType+`"`), []byte(`"type":"\ud800"`), 1)
	case 5, 6, 7, 8, 9, 10:
		token := map[int]string{5: "1.5", 6: "1.0", 7: "1e0", 8: "-0", 9: "9007199254740992", 10: "-9007199254740992"}[n]
		return bytes.Replace(raw, []byte(`"type":"`+codeType+`"`), []byte(`"type":`+token), 1)
	case 11:
		e["extra"] = true
	case 12:
		body["extra"] = true
	case 13:
		delete(e, "sig")
	case 14:
		delete(body, "type")
	case 15:
		e["body"] = []any{}
	case 16:
		if enroll {
			body["host"] = nil
		} else {
			body["name"] = nil
		}
	case 17:
		return append([]byte{239, 187, 191}, raw...)
	case 18:
		var nested any = true
		for i := 0; i < 15; i++ { // Envelope and body add two containers: exactly depth 17.
			nested = []any{nested}
		}
		body["extra"] = nested
	case 19:
		e["sig"] = "+" + str(e["sig"])[1:]
	case 20:
		e["sig"] = str(e["sig"]) + "="
	case 21:
		s := str(e["sig"])
		alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		i := strings.IndexByte(alphabet, s[len(s)-1])
		e["sig"] = s[:len(s)-1] + string(alphabet[i+1])
	case 22:
		e["sig"] = enc(make([]byte, 63))
	case 23:
		e["id"] = "sha256:" + strings.ToUpper(strings.TrimPrefix(str(e["id"]), "sha256:"))
	case 24:
		e["id"] = "sha256:" + strings.Repeat("0", 63)
	case 25:
		body["type"] = "other/1"
	case 26, 27, 28, 29, 30, 31:
		value := map[int]string{26: "2030-01-01T00:00:00.0Z", 27: "2030-01-01T00:00:00+00:00", 28: "2030-01-01T00:00:00z", 29: "2030-02-30T00:00:00Z", 30: "2030-01-01T00:00:60Z", 31: "1969-12-31T23:59:59Z"}[n]
		if enroll {
			mapv(body["keys"].([]any)[0])["not_before"] = value
		} else {
			body["iat"] = value
		}
	}
	if n == 12 || n == 14 || n == 15 || n == 16 || n == 18 || n == 25 || n >= 26 {
		p := append([]byte("swarma-registrar "+codeType+"\n"), ccj(e["body"])...)
		h := sha256.Sum256(p)
		e["id"] = "sha256:" + hex.EncodeToString(h[:])
		k := host
		if enroll {
			k = publisher
		}
		e["sig"] = enc(ed25519.Sign(k, p))
	}
	return ccj(e)
}
func enrollmentCase(r row) M {
	f := fixture()
	rg := mapv(f["registry"])
	body := enrollment("host-a", edpub(host), 1)
	pubKey := publisher
	if r.ID == "PE2" || r.ID == "E44" {
		mapv(body["keys"].([]any)[0])["key"] = pPublic
	}
	if r.ID == "PE3" {
		mapv(body["uid_map"].([]any)[0])["exe"] = "/usr/bin/client"
	}
	names := mapv(body["names"])
	uid := mapv(body["uid_map"].([]any)[0])
	key := mapv(body["keys"].([]any)[0])
	multi := false
	other := func() M {
		b := enrollment("host-b", edpub(extra("host-b")), 1)
		mapv(b["names"])["explicit"] = []any{"legacy.b"}
		return b
	}
	files := func(bodies ...M) {
		a := []any{}
		for i, b := range bodies {
			a = append(a, file(fmt.Sprintf("enrollments/%02d.json", i), record(b)))
		}
		rg["files"] = a
		multi = true
	}
	previous := func(bodies ...M) {
		a := []any{}
		for i, b := range bodies {
			a = append(a, file(fmt.Sprintf("enrollments/%02d.json", i), record(b)))
		}
		rg["previous_files"] = a
		rg["previous_revision"] = strings.Repeat("a", 40)
		rg["revision"] = strings.Repeat("b", 40)
	}
	switch r.ID {
	case "E36":
		body["sigs"] = []any{}
	case "E37":
		body["sigs"] = nil
	case "E38":
		body["host"] = "host_a"
	case "E39":
		body["host"] = strings.Repeat("a", 33)
	case "E40":
		names["prefix"] = "other_"
	case "E41":
		body["keys"] = []any{}
	case "E42":
		a := []any{}
		for i := 0; i < 17; i++ {
			a = append(a, M{"key": edpub(extra(fmt.Sprintf("key-%d", i))), "not_before": ts(0), "not_after": ts(240)})
		}
		body["keys"] = a
	case "E43":
		second := clone(key)
		key["not_after"] = ts(60)
		second["not_before"] = ts(60)
		body["keys"] = []any{key, second}
	case "E44":
		key["key"] = "p256:" + enc(host.Public().(ed25519.PublicKey))
	case "E45":
		key["not_after"] = key["not_before"]
	case "E46":
		key["not_after"] = ts(-1)
	case "E47":
		key["extra"] = true
	case "E48":
		names["explicit"] = []any{"legacy.dev", "legacy.dev"}
	case "E49":
		names["explicit"] = []any{"bad/name"}
	case "E50":
		delete(body, "uid_map")
	case "E51":
		uid["uid"] = "1001"
	case "E52":
		uid["uid"] = 0
	case "E53":
		uid["uid"] = int64(4294967295)
	case "E54":
		uid["uid"] = -1
	case "E55":
		body["uid_map"] = []any{uid, clone(uid)}
	case "E56":
		uid["names"] = []any{"host-b_project_dev"}
	case "E57":
		uid["names"] = []any{}
	case "E58":
		uid["names"] = []any{"host-a_*"}
	case "E59":
		second := clone(uid)
		second["uid"] = 1002
		body["uid_map"] = []any{uid, second}
	case "E60":
		uid["exe"] = "bin/client"
	case "E61":
		uid["exe"] = "/usr/../bin/client"
	case "E62":
		uid["exe"] = "/usr//bin/client"
	case "E63":
		uid["exe"] = "/usr/bin/\x00client"
	case "E64":
		uid["exe"] = "/" + strings.Repeat("a", 4096)
	case "E65":
		uid["extra"] = true
	case "E66":
		body["seq"] = 0
	case "E67":
		body["seq"] = "1"
	case "E68":
		body["state"] = "disabled"
	case "E69":
		files(body, clone(body))
	case "E70":
		b := other()
		mapv(b["keys"].([]any)[0])["key"] = edpub(host)
		files(body, b)
	case "E71":
		b := other()
		mapv(b["names"])["explicit"] = []any{"legacy.dev"}
		files(body, b)
	case "E72":
		b := other()
		mapv(b["names"])["explicit"] = []any{"host-a_project_dev"}
		files(body, b)
	case "E73":
		body["state"] = "revoked"
		next := clone(body)
		next["seq"] = 2
		next["state"] = "active"
		files(body, next)
	case "E74":
		old := clone(body)
		old["seq"] = 2
		previous(body, old)
	case "E75":
		previous(body)
		names["explicit"] = []any{"legacy.changed"}
	case "E76":
		b := other()
		b["state"] = "revoked"
		previous(body, b)
	case "E77":
		previous(body)
		rg["previous_revision"] = strings.Repeat("b", 40)
		rg["revision"] = strings.Repeat("a", 40)
		rg["descendant"] = false
	case "E78":
		rg["commit_signature_valid"] = false
	case "E79":
		rg["pin_is_exact"] = false
		rg["revision"] = "main"
	case "E80":
		invalid := clone(body)
		invalid["seq"] = 2
		invalid["keys"] = []any{}
		files(body, invalid)
	case "E81":
		rg["rollback_state_available"] = false
		previous(body)
	case "E83":
		uid["exe"] = "/usr/./bin/client"
	case "E84":
		uid["exe"] = "/usr/bin/client/"
	case "E85":
		uid["exe"] = "/"
	case "E86":
		uid["names"] = []any{"host-a_project_dev", "host-a_project_dev"}
	case "E88": // Entry kind changed after constructing the envelope.
	case "E89": // Count cap uses an explicit repeated byte fixture, not hidden files.
	case "E90":
		rg["station_hosts"] = []any{"host-b"}
	case "E91":
		body["uid_map"] = []any{}
	case "E92":
		a := []any{}
		for i := 0; i < 257; i++ {
			a = append(a, M{"uid": i + 1, "names": []any{fmt.Sprintf("host-a_project_r%d", i)}})
		}
		body["uid_map"] = a
	case "E93":
		a := []any{}
		for i := 0; i < 65; i++ {
			a = append(a, fmt.Sprintf("host-a_project_r%d", i))
		}
		uid["names"] = a
	case "E94":
		a := []any{}
		for i := 0; i < 257; i++ {
			a = append(a, fmt.Sprintf("legacy.%d", i))
		}
		names["explicit"] = a
	case "E95":
		body["host"] = "HOST-A"
	case "E96":
		body["host"] = ""
	case "E97":
		names["extra"] = true
	case "E98":
		uid["exe"] = "/usr\\bin/client"
	case "E99":
		uid["exe"] = "/usr/bin/cli\nent"
	case "E100":
		names["explicit"] = []any{strings.Repeat("a", 243)}
	case "E101":
		body["state"] = "revoked"
		b := other()
		mapv(b["keys"].([]any)[0])["key"] = edpub(host)
		files(body, b)
	case "E102": // Aggregate cap is computed from actual repeated padded bytes below.
	case "E103":
		rg["persist_available"] = false
	case "E104":
		previous(body)
		rg["approved"] = false
	case "E105":
		rg["publisher_key"] = nil
	case "E106":
		body["sigs"] = []any{}
		body["keys"] = []any{}
	case "E107", "E108", "E109":
		reserved := record(clone(body))
		mapv(reserved["body"])["sigs"] = []any{}
		reserved["id"] = id(mapv(reserved["body"]))
		reserved["sig"] = enc(ed25519.Sign(publisher, preimage(mapv(reserved["body"]))))
		bad := record(body)
		bad["sig"] = enc(make([]byte, 64))
		a, z := bad, reserved
		if r.ID == "E108" {
			a, z = reserved, bad
		}
		rg["files"] = []any{file("enrollments/a.json", a), file("enrollments/z.json", z)}
		multi = true
		if r.ID == "E109" {
			rg["files"] = []any{file("enrollments/a.json", reserved), M{"path": "enrollments/z.json", "kind": "regular", "repeat": 1, "bytes_base64": enc(commonDefect(record(body), 1, true))}}
		}
	case "E110":
		old := clone(body)
		old["seq"] = 2
		previous(body, old)
		b := other()
		mapv(b["keys"].([]any)[0])["key"] = edpub(host)
		files(body, b)
	case "E111":
		next := clone(body)
		next["seq"] = 2
		mapv(next["names"])["explicit"] = []any{}
		b := other()
		mapv(b["names"])["explicit"] = []any{"legacy.dev"}
		files(body, next, b)
	case "PE4":
		next := clone(body)
		next["seq"] = 2
		files(body, next, other())
	case "PE5":
		next := clone(body)
		next["seq"] = 2
		next["state"] = "revoked"
		files(body, next)
	case "PE6":
		previous(body)
		next := clone(body)
		next["seq"] = 2
		files(body, next)
		rg["revision"] = strings.Repeat("b", 40)
	case "PE7":
		body["keys"] = append(body["keys"].([]any), M{"key": pPublic, "not_before": ts(0), "not_after": "2031-01-01T00:00:00Z"})
	case "PE8":
		delete(body, "uid_map")
		rg["station_hosts"] = []any{"host-b"}
		rg["nonstation_hosts"] = []any{"host-a"}
	case "PE9":
		previous(body)
		rg["previous_publisher_key"] = edpub(publisher)
		pubKey = extra("publisher-rotation")
		rg["publisher_key"] = edpub(pubKey)
		rg["revision"] = strings.Repeat("b", 40)
	case "PE10":
		uid["uid"] = int64(4294967294)
	case "PE11":
		label := strings.Repeat("a", 32)
		body = enrollment(label, edpub(host), 1)
		b := enrollment("b", edpub(extra("short-host")), 1)
		mapv(b["names"])["explicit"] = []any{"legacy.b"}
		files(body, b)
		rg["station_hosts"] = []any{label, "b"}
	case "PE12":
		body["seq"] = int64(9007199254740991)
	case "PE13":
		next := clone(body)
		next["seq"] = 2
		mapv(next["names"])["explicit"] = []any{}
		third := clone(body)
		third["seq"] = 3
		files(body, next, third)
	}
	env := envelope(body, pubKey)
	raw := ccj(env)
	n, _ := strconv.Atoi(strings.TrimPrefix(r.ID, "E"))
	if n >= 1 && n <= 31 {
		raw = commonDefect(env, n, true)
	}
	switch r.ID {
	case "E32":
		env["id"] = "sha256:" + strings.Repeat("0", 64)
		raw = ccj(env)
	case "E33":
		env["sig"] = enc(ed25519.Sign(extra("unapproved-publisher"), preimage(body)))
		raw = ccj(env)
	case "E34":
		env["sig"] = enc(ed25519.Sign(host, preimage(body)))
		raw = ccj(env)
	case "E35":
		env["sig"] = enc(ed25519.Sign(publisher, append([]byte("swarma-registrar registration/1\n"), ccj(body)...)))
		raw = ccj(env)
	case "E82":
		raw = append(raw, bytes.Repeat([]byte{' '}, 65537-len(raw))...)
	case "E87":
		sig := dec(str(env["sig"]))
		copy(sig[32:], little(orderL))
		env["sig"] = enc(sig)
		raw = ccj(env)
	}
	if !multi {
		rg["files"] = []any{M{"path": "enrollments/a.json", "kind": "regular", "repeat": 1, "bytes_base64": enc(raw)}}
	}
	fs := rg["files"].([]any)
	if r.ID == "E88" {
		mapv(fs[0])["kind"] = "symlink"
	}
	if r.ID == "E89" {
		mapv(fs[0])["repeat"] = 10001
		mapv(fs[0])["path_template"] = "enrollments/%05d.json"
	}
	if r.ID == "E102" {
		mapv(fs[0])["repeat"] = 257
		mapv(fs[0])["path_template"] = "enrollments/%05d.json"
		mapv(fs[0])["bytes_base64"] = enc(append(raw, bytes.Repeat([]byte{' '}, 65536-len(raw))...))
	}
	raw = dec(str(mapv(fs[0])["bytes_base64"]))
	return M{"row": r.ID, "domain": r.Domain, "claim": r.Rule + ": " + r.Boundary, "positive_control": r.Control, "mode": "registry", "input": M{"bytes_base64": enc(raw)}, "fixture": f, "expected": M{"code": r.Code}}
}
func codecCase(r row) M {
	var value any
	wire := ""
	mode := "codec"
	switch r.ID {
	case "PC1":
		value = M{"𐀀": 1, "\ue000": 2}
	case "PC2":
		value = M{"b": 2, "a": 1}
		wire = " { \"b\" : 2, \"a\" : 1 } \n"
	case "PC3":
		value = []any{3, 1, 2}
		for i := 0; i < 15; i++ {
			value = []any{value}
		} // Preserve inner array order at allowed depth 16.
	case "PC4":
		value = "\b\f\n\r\t\x01\"\\"
	case "PC5":
		value = "/<>&é\u2028\u2029"
	case "PC6":
		value = []any{int64(-9007199254740991), 0, int64(9007199254740991)}
	case "PC7":
		value = []any{true, false, nil}
	case "PC8":
		value = "𐀀"
		wire = `"\ud800\udc00"`
	case "PC9":
		value = []any{"é", "e\u0301"}
	case "PC10":
		value = M{"body": M{"nested": M{"sig": "preserve"}}, "sig": "exclude"}
		mode = "codec-extract"
	}
	canonical := ccj(value)
	if wire == "" {
		wire = string(canonical)
	}
	if mode == "codec-extract" {
		canonical = ccj(mapv(value)["body"])
	}
	return M{"row": r.ID, "domain": r.Domain, "claim": r.Rule + ": " + r.Boundary, "positive_control": r.Control, "mode": mode, "input": M{"bytes_base64": enc([]byte(wire))}, "fixture": fixture(), "expected": M{"code": "accept", "canonical_bytes_base64": enc(canonical)}}
}

// The generator constructs explicit expected-state oracles from the planned
// outcomes; the Python checker derives outcomes independently from input bytes.
func finish(v M) {
	mode := str(v["mode"])
	if strings.HasPrefix(mode, "codec") {
		return
	}
	f := mapv(v["fixture"])
	expected := mapv(v["expected"])
	code := str(expected["code"])
	if mode == "registry" {
		expected["state"] = M{"authority_installed": code == "accept", "prior_authority_preserved": code != "accept", "admission_ready": code == "accept", "nonce_cache": f["nonce_cache"], "limiter_events": f["limiter_events"], "audit_outcomes": []any{}, "authority": authority(mapv(f["registry"]), code != "accept")}
		return
	}
	if f["final_revoked"] == true || f["post_audit_revoked"] == true {
		rg := clone(mapv(f["registry"]))
		fs := rg["files"].([]any)
		env := parse(dec(str(mapv(fs[0])["bytes_base64"])))
		body := mapv(env["body"])
		body["seq"] = num(body["seq"]) + 1
		body["state"] = "revoked"
		rg["files"] = append(fs, file("enrollments/revoked.json", record(body)))
		rg["revision"] = strings.Repeat("b", 40)
		f["scheduled_registry"] = rg
	}
	cache := append([]any{}, f["nonce_cache"].([]any)...)
	events := append([]any{}, f["limiter_events"].([]any)...)
	audit := []any{}
	fenced := f["clock_fenced"] == true || f["startup_verified"] != true
	healthy := f["clock_healthy"] == true
	barrier := num(f["start_barrier"])
	signer := f["signer_available"] == true
	generation := f["signing_generation"]
	apply := func(raw []byte, c string, now int64, main bool) {
		late := main && (f["final_revoked"] == true || f["post_audit_revoked"] == true || f["final_now"] != nil || f["post_audit_generation"] != nil)
		charged := c == "accept" || c == "nonce_replayed" || c == "service_unavailable" || late || (c == "audit_unavailable" && str(v["row"]) != "R106")
		if charged {
			e := parse(raw)
			b := mapv(e["body"])
			filtered := []any{}
			for _, event := range events {
				if num(mapv(event)["at"]) > num(f["monotonic_now"])-60 {
					filtered = append(filtered, event)
				}
			}
			events = filtered
			events = append(events, M{"at": f["monotonic_now"], "key": b["key"], "name": b["name"]})
			if c != "nonce_replayed" {
				cache = append(cache, M{"key": b["key"], "nonce": b["nonce"], "expires": parseTime(str(b["exp"])) + 30})
			}
		}
		if !healthy {
			fenced = true
		}
		a := mapv(f["audit"])
		if a["local_available"] == true {
			if c == "accept" {
				audit = append(audit, "issued")
			} else {
				if main && (f["post_audit_revoked"] == true || f["post_audit_generation"] != nil || str(v["row"]) == "R96") {
					audit = append(audit, "issued")
				}
				audit = append(audit, c)
			}
		}
	}
	transition := func(item M) {
		switch item["event"] {
		case "request":
			apply(dec(str(item["bytes_base64"])), str(mapv(item["expected"])["code"]), num(item["now"]), false)
		case "restart":
			cache = []any{}
			events = []any{}
			healthy = item["startup_verified"] == true
			fenced = !healthy
			barrier = num(item["actual_start_millis"])/1000 + 31
		case "clock":
			healthy = item["healthy"] == true
			if !healthy {
				fenced = true
			}
		case "signer":
			signer = item["available"] == true
		}
	}
	for _, item := range v["before"].([]any) {
		transition(mapv(item))
	}
	apply(dec(str(mapv(v["input"])["bytes_base64"])), code, num(f["now"]), true)
	if code == "accept" {
		env := parse(dec(str(mapv(v["input"])["bytes_base64"])))
		expected["jwt"] = jwt(env, num(f["now"]))
	}
	if f["post_audit_generation"] != nil {
		generation = f["post_audit_generation"]
	}
	for _, item := range v["after"].([]any) {
		transition(mapv(item))
	}
	expected["state"] = M{"nonce_cache": cache, "limiter_events": events, "audit_outcomes": audit, "clock_fenced": fenced, "start_barrier": barrier, "signer_ready": signer, "audit_ready": mapv(f["audit"])["local_available"] == true && mapv(f["audit"])["remote_ack"] == true, "registry_ready": mapv(f["registry"])["available"], "signing_generation": generation, "scheduled_revocation_applied": f["final_revoked"] == true || f["post_audit_revoked"] == true}
	auth := mapv(f["registry"])
	if f["scheduled_registry"] != nil {
		auth = mapv(f["scheduled_registry"])
	}
	mapv(expected["state"])["authority"] = authority(auth, false)
	if code == "accept" && str(v["row"]) == "PR16" {
		e := parse(dec(str(mapv(v["input"])["bytes_base64"])))
		b := mapv(e["body"])
		kh := sha256.Sum256([]byte(str(b["key"])))
		line := M{"v": 1, "seq": 1, "at": ts(num(f["now"]) - epoch), "instance": nonce(32), "jti": e["id"], "key_id": "sha256:" + hex.EncodeToString(kh[:]), "host": "host-a", "name": b["name"], "outcome": "issued", "code": "issued", "http_status": 200, "registry_revision": mapv(f["registry"])["revision"], "jwt_iat": num(f["now"]), "jwt_exp": num(f["now"]) + 120, "request_bytes": len(dec(str(mapv(v["input"])["bytes_base64"]))), "prev_hash": strings.Repeat("0", 64)}
		lineBytes := append(ccj(line), '\n')
		h := sha256.Sum256(lineBytes)
		expected["audit_line_base64"] = enc(lineBytes)
		expected["audit_line_sha256"] = hex.EncodeToString(h[:])
	}
}
func authority(rg M, previous bool) M {
	field := "files"
	revision := rg["revision"]
	if previous {
		field = "previous_files"
		revision = rg["previous_revision"]
	}
	ids := []string{}
	for _, item := range rg[field].([]any) {
		f := mapv(item)
		e := parse(dec(str(f["bytes_base64"])))
		ids = append(ids, str(e["id"]))
	}
	sort.Strings(ids)
	list := []any{}
	for _, v := range ids {
		list = append(list, v)
	}
	return M{"revision": revision, "record_ids": list}
}
func parseTime(s string) int64 {
	t, e := time.Parse("2006-01-02T15:04:05Z", s)
	must(e)
	return t.Unix()
}
func main() {
	check := flag.Bool("check", false, "refuse any committed byte or file-set difference")
	out := flag.String("out", "vectors", "vector tree to write or compare (control fixtures only)")
	flag.Parse()
	data, e := os.ReadFile("vectors/keys/seeds.json")
	must(e)
	var seedDoc M
	must(json.Unmarshal(data, &seedDoc))
	seeds = map[string]string{}
	for k, v := range seedDoc {
		if text, ok := v.(string); ok {
			seeds[k] = text
		}
	}
	expectedSeeds := map[string]string{
		"host_ed25519":         "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		"enrollment_publisher": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		"registrar_jwt":        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
		"host_p256":            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"}
	for name, want := range expectedSeeds {
		if seeds[name] != want {
			fmt.Fprintln(os.Stderr, "FAIL: unpublished test seed")
			os.Exit(1)
		}
	}
	host = ed25519.NewKeyFromSeed(hx(seeds["host_ed25519"]))
	publisher = ed25519.NewKeyFromSeed(hx(seeds["enrollment_publisher"]))
	jwtKey = ed25519.NewKeyFromSeed(hx(seeds["registrar_jwt"]))
	pScalar = new(big.Int).SetBytes(hx(seeds["host_p256"]))
	x, y := elliptic.P256().ScalarBaseMult(pScalar.Bytes())
	pPublic = "p256:" + enc(elliptic.MarshalCompressed(elliptic.P256(), x, y))
	source, e := os.ReadFile("spec/registrar.md")
	must(e)
	table := strings.Split(strings.Split(string(source), "## Appendix B.")[1], "### B.1")[0]
	outputs := map[string][]byte{}
	order := []string{}
	for _, line := range strings.Split(table, "\n") {
		columns := strings.Split(line, "|")
		if len(columns) != 8 {
			continue
		}
		c := []string{}
		for _, v := range columns[1:7] {
			c = append(c, strings.TrimSpace(v))
		}
		if c[1] != "registration/1" && c[1] != "enrollment/1" {
			continue
		}
		code := strings.TrimSpace(strings.Split(c[4], ";")[0])
		if strings.HasPrefix(code, "accept") {
			code = "accept"
		}
		r := row{c[0], c[1], c[2], c[3], code, c[5]}
		var v M
		switch {
		case strings.HasPrefix(r.ID, "PC"):
			v = codecCase(r)
		case r.Domain == "registration/1":
			v = registrationCase(r)
		default:
			v = enrollmentCase(r)
		}
		finish(v)
		domain := strings.ReplaceAll(r.Domain, "/", "-")
		group := "0-negative"
		if strings.HasPrefix(r.ID, "P") {
			group = "1-positive"
		}
		path := filepath.Join(*out, domain, group, r.ID+".json")
		outputs[path] = jsonBytes(v)
		order = append(order, path)
	}
	primary := M{"host_ed25519": edpub(host), "host_p256": pPublic, "enrollment_publisher": edpub(publisher), "registrar_jwt": edpub(jwtKey)}
	labels := []string{}
	for label := range derivedKeys {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	derivations := []any{}
	for _, label := range labels {
		k := derivedKeys[label]
		derivations = append(derivations, M{"label": label, "seed_hex": hex.EncodeToString(k.Seed()), "public_key": edpub(k)})
	}
	keyPath := filepath.Join(*out, "keys", "public-keys.json")
	outputs[keyPath] = jsonBytes(M{"test_only": true, "primary_public_keys": primary, "derived_from": "host_ed25519", "derivations": derivations})
	order = append(order, keyPath)
	seedOutput := M{"test_only": true}
	for name, value := range expectedSeeds {
		seedOutput[name] = value
	}
	seedPath := filepath.Join(*out, "keys", "seeds.json")
	outputs[seedPath] = jsonBytes(seedOutput)
	order = append(order, seedPath)
	mismatches := 0
	for _, path := range order {
		expected := outputs[path]
		if *check {
			actual, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(actual, expected) {
				fmt.Printf("DIFF %s\n", filepath.Base(path))
				mismatches++
			}
		} else {
			must(os.MkdirAll(filepath.Dir(path), 0755))
			must(os.WriteFile(path, expected, 0644))
		}
	}
	for _, domain := range []string{"registration-1", "enrollment-1", "keys"} {
		must(filepath.WalkDir(filepath.Join(*out, domain), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if *check && os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, ".json") {
				if _, ok := outputs[path]; !ok {
					fmt.Printf("UNEXPECTED %s\n", filepath.Base(path))
					mismatches++
				}
			}
			return nil
		}))
	}
	if mismatches > 0 {
		fmt.Printf("FAIL: %d vector differences\n", mismatches)
		os.Exit(1)
	}
	if *check {
		fmt.Printf("PASS: %d vectors match regenerated bytes and file set\n", len(order)-2)
	} else {
		fmt.Printf("WROTE: %d deterministic vectors and public test-key manifest (negative rows before controls)\n", len(order)-2)
	}
}
