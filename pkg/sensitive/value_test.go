package sensitive

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const plaintext = "hunter2-super-secret"

func TestValueNeverRendersPlaintext(t *testing.T) {
	v := FromString(plaintext)

	for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%x", "%X", "%q", "%d"} {
		if out := fmt.Sprintf(verb, v); strings.Contains(out, plaintext) || out != redacted {
			t.Errorf("fmt %s rendered %q", verb, out)
		}
	}

	wrapped := struct {
		Name  string
		Value Value
	}{"db", v}
	if out := fmt.Sprintf("%+v", wrapped); strings.Contains(out, plaintext) {
		t.Errorf("struct formatting leaked: %q", out)
	}

	j, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(j, []byte(plaintext)) {
		t.Errorf("json leaked: %s", j)
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("test", "value", v, "nested", slog.GroupValue(slog.Any("v", v)))
	if strings.Contains(buf.String(), plaintext) {
		t.Errorf("slog leaked: %s", buf.String())
	}
}

func TestRevealAndWipe(t *testing.T) {
	src := []byte(plaintext)
	v := New(src)
	clear(src)

	if v.RevealString() != plaintext {
		t.Fatalf("New must copy its input")
	}

	underlying := v.Reveal()
	v.Wipe()
	if !v.IsZero() {
		t.Fatal("expected Value to be empty after Wipe")
	}
	if !bytes.Equal(underlying, make([]byte, len(plaintext))) {
		t.Fatal("expected underlying bytes to be zeroed")
	}
}

func TestUnmarshalJSON(t *testing.T) {
	var in struct{ V Value }
	if err := json.Unmarshal([]byte(`{"V":"hunter2"}`), &in); err != nil || in.V.RevealString() != "hunter2" {
		t.Fatalf("got %v %v", in.V.RevealString(), err)
	}
	err := json.Unmarshal([]byte(`{"V":{"hunter2":1}}`), &in)
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error must not echo input: %v", err)
	}
	out, _ := json.Marshal(in)
	if strings.Contains(string(out), "hunter2") {
		t.Fatal("round trip leaked the value")
	}
}
