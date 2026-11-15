// Package sensitive provides a container for secret material (secret values,
// credentials, client secrets) that refuses to render its contents through
// fmt, log/slog, encoding/json or encoding.TextMarshaler.
//
// SecretMesh never persists secret values. Wrapping them in Value from the
// moment they enter the process keeps them out of logs, traces, error messages
// and serialized payloads by default; reading the bytes requires an explicit
// call to Reveal.
package sensitive

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

const redacted = "[REDACTED]"

// Value holds sensitive bytes. The zero value is empty.
type Value struct {
	b []byte
}

// New copies b into a new Value. Callers should clear their own copy of b.
func New(b []byte) Value {
	c := make([]byte, len(b))
	copy(c, b)
	return Value{b: c}
}

// FromString creates a Value from s. Go strings are immutable and cannot be
// wiped, so prefer New when the source is already a byte slice.
func FromString(s string) Value {
	return Value{b: []byte(s)}
}

// Reveal returns the underlying bytes. Do not retain, log or persist them.
func (v Value) Reveal() []byte { return v.b }

// RevealString returns the contents as a string. Do not retain, log or persist it.
func (v Value) RevealString() string { return string(v.b) }

// IsZero reports whether the Value is empty.
func (v Value) IsZero() bool { return len(v.b) == 0 }

// Wipe overwrites the underlying bytes with zeros and empties the Value.
func (v *Value) Wipe() {
	clear(v.b)
	v.b = nil
}

// String implements fmt.Stringer.
func (Value) String() string { return redacted }

// GoString implements fmt.GoStringer.
func (Value) GoString() string { return redacted }

// Format implements fmt.Formatter so every verb (%s, %v, %+v, %#v, %x, %q, ...) is redacted.
func (Value) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue implements slog.LogValuer.
func (Value) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON implements json.Marshaler.
func (Value) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (Value) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// UnmarshalJSON accepts a JSON string, so request bodies can decode secret
// material straight into a Value. Errors never include the input.
func (v *Value) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("sensitive value must be a JSON string")
	}
	*v = FromString(s)
	return nil
}
