package ccj

import (
	"bytes"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/refusal"
)

// These cases reject ambiguous JSON values while the adjacent control canonicalizes legal wire variations.
func TestStrictParsing(t *testing.T) {
	bad := []string{`{"a":1,"\u0061":2}`, `{"a":{"x":0,"x":1}}`, `1.0`, `1e0`, `-0`, `9007199254740992`, `-9007199254740992`, `"\ud800"`, `"\udc00"`, `"\ud800x"`, `"\ud800\u0041"`, `"` + string([]byte{0xff}) + `"`, "\xef\xbb\xbf{}", `{} {}`, `01`, `+1`, `"\x00"`, `{"x":}`, `[1,]`, `{"x":1,}`, `"` + string(rune(1)) + `"`, `truex`, ``, strings.Repeat(`{"x":`, 16) + `{}` + strings.Repeat(`}`, 16)}
	for _, input := range bad {
		t.Run(input, func(t *testing.T) {
			_, err := Parse([]byte(input), refusal.RegistrationMalformed)
			if !refusal.Is(err, refusal.RegistrationMalformed) {
				t.Fatalf("got %v", err)
			}
		})
	}
	good := []struct{ in, want string }{
		{` { "z": 1, "a": "\u0061\/\u003c\u003e\u0026" } `, `{"a":"a/<>&","z":1}`},
		{`{"😀":0,"\ue000":1}`, "{\"\ue000\":1,\"😀\":0}"},
		{`["\b\f\n\r\t\u0001\u001A",true,false,null,-9007199254740991,9007199254740991,0]`, `["\b\f\n\r\t\u0001\u001a",true,false,null,-9007199254740991,9007199254740991,0]`},
		{`["\ud83d\ude00","é","e\u0301",2,1]`, "[\"😀\",\"é\",\"é\",2,1]"},
		{strings.Repeat(`{"x":`, 15) + `{}` + strings.Repeat(`}`, 15), strings.Repeat(`{"x":`, 15) + `{}` + strings.Repeat(`}`, 15)},
	}
	for _, tc := range good {
		v, err := Parse([]byte(tc.in), refusal.RegistrationMalformed)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Marshal(v, refusal.RegistrationMalformed)
		if err != nil || !bytes.Equal(got, []byte(tc.want)) {
			t.Fatalf("%s: %q, %v", tc.in, got, err)
		}
	}
	_, err := Parse([]byte(`1.0`), refusal.EnrollmentMalformed)
	if !refusal.Is(err, refusal.EnrollmentMalformed) {
		t.Fatal(err)
	}
}

// The serializer must refuse values outside CCJ rather than truncating or replacing them.
func TestSerializerRefusesUnsupportedValues(t *testing.T) {
	for _, v := range []any{float64(1), int64(9007199254740992), string([]byte{0xff}), map[string]any{string([]byte{0xff}): int64(1)}} {
		if _, err := Marshal(v, refusal.RegistrationMalformed); !refusal.Is(err, refusal.RegistrationMalformed) {
			t.Fatalf("%T: %v", v, err)
		}
	}
	if _, err := Marshal(map[string]any{"ok": int64(1)}, refusal.RegistrationMalformed); err != nil {
		t.Fatal(err)
	}
}
