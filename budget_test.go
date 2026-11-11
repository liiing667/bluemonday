package bluemonday

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
)

func TestSanitizeReaderToWriterDefaultIsUnlimited(t *testing.T) {
	p := UGCPolicy()
	input := strings.Repeat(`<p>Hello &amp; world</p>`, 1000)

	var out bytes.Buffer
	if err := p.SanitizeReaderToWriter(strings.NewReader(input), &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := out.String(), p.Sanitize(input); got != want {
		t.Fatalf("output differs from Sanitize():\ngot  %q\nwant %q", got, want)
	}
}

func TestSanitizeReaderToWriterInputBudget(t *testing.T) {
	p := UGCPolicy()
	input := `<p>Hello</p>`

	var out bytes.Buffer
	err := p.SanitizeReaderToWriter(
		strings.NewReader(input),
		&out,
		SanitizeBudget{MaxInputBytes: int64(len(input) - 1)},
	)
	if !errors.Is(err, ErrInputLimitExceeded) {
		t.Fatalf("expected input limit error, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("writer received partial output: %q", out.String())
	}

	err = p.SanitizeReaderToWriter(
		strings.NewReader(input),
		&out,
		SanitizeBudget{MaxInputBytes: int64(len(input))},
	)
	if err != nil {
		t.Fatalf("unexpected error at exact input limit: %v", err)
	}
	if got, want := out.String(), p.Sanitize(input); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSanitizeReaderToWriterNodeBudget(t *testing.T) {
	p := UGCPolicy()
	input := `<p>Hello</p>`

	// <p>, the text token, and </p>.
	const nodes = 3

	var out bytes.Buffer
	err := p.SanitizeReaderToWriter(
		strings.NewReader(input),
		&out,
		SanitizeBudget{MaxNodes: nodes - 1},
	)
	if !errors.Is(err, ErrNodeLimitExceeded) {
		t.Fatalf("expected node limit error, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("writer received partial output: %q", out.String())
	}

	err = p.SanitizeReaderToWriter(
		strings.NewReader(input),
		&out,
		SanitizeBudget{MaxNodes: nodes},
	)
	if err != nil {
		t.Fatalf("unexpected error at exact node limit: %v", err)
	}
	if got, want := out.String(), p.Sanitize(input); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSanitizeReaderToWriterOutputBudgetUsesSanitizedBytes(t *testing.T) {
	p := UGCPolicy()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "tag stripping",
			input: `<b>Hello</b>`,
		},
		{
			name:  "entity expansion",
			input: `<p>Hello &amp; world</p>`,
		},
		{
			name:  "url rewriting",
			input: `<a href="https://example.com/?a=1&amp;b=2">link</a>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := p.Sanitize(tt.input)

			var out bytes.Buffer
			err := p.SanitizeReaderToWriter(
				strings.NewReader(tt.input),
				&out,
				SanitizeBudget{MaxOutputBytes: int64(len(want)) - 1},
			)
			if !errors.Is(err, ErrOutputLimitExceeded) {
				t.Fatalf("expected output limit error, got %v", err)
			}
			if out.Len() != 0 {
				t.Fatalf("writer received partial output: %q", out.String())
			}

			err = p.SanitizeReaderToWriter(
				strings.NewReader(tt.input),
				&out,
				SanitizeBudget{MaxOutputBytes: int64(len(want))},
			)
			if err != nil {
				t.Fatalf("unexpected error at exact output limit: %v", err)
			}
			if got := out.String(); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestSanitizeReaderToWriterOutputBudgetUsesStyleOutput(t *testing.T) {
	p := NewPolicy()
	p.AllowAttrs("style").OnElements("p")
	p.AllowStyles("color").Matching(regexp.MustCompile(`^#[0-9a-f]{6}$`)).OnElements("p")

	input := `<p style="color: #ff0000">Hello</p>`
	want := p.Sanitize(input)

	var out bytes.Buffer
	err := p.SanitizeReaderToWriter(
		strings.NewReader(input),
		&out,
		SanitizeBudget{MaxOutputBytes: int64(len(want)) - 1},
	)
	if !errors.Is(err, ErrOutputLimitExceeded) {
		t.Fatalf("expected output limit error, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("writer received partial output: %q", out.String())
	}
}

func TestSanitizeReaderToWriterReaderFailure(t *testing.T) {
	p := UGCPolicy()
	sentinel := errors.New("reader failed")
	reader := &failingReader{
		r:   strings.NewReader(`<p>Hello</p>`),
		err: sentinel,
	}

	var out bytes.Buffer
	err := p.SanitizeReaderToWriter(reader, &out)
	if !errors.Is(err, ErrReadFailed) {
		t.Fatalf("expected read failure, got %v", err)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected underlying reader error, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("writer received partial output: %q", out.String())
	}
}

func TestSanitizeReaderToWriterWriterFailure(t *testing.T) {
	p := UGCPolicy()
	sentinel := errors.New("writer failed")
	w := &failingWriter{err: sentinel}

	err := p.SanitizeReaderToWriter(strings.NewReader(`<p>Hello</p>`), w)
	if !errors.Is(err, ErrWriteFailed) {
		t.Fatalf("expected write failure, got %v", err)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected underlying writer error, got %v", err)
	}
}

func TestPolicyBudgetMethodsAndPerCallOverride(t *testing.T) {
	p := UGCPolicy().SetMaxOutputBytes(1)
	input := `<p>Hello</p>`

	var out bytes.Buffer
	err := p.SanitizeReaderToWriter(strings.NewReader(input), &out)
	if !errors.Is(err, ErrOutputLimitExceeded) {
		t.Fatalf("expected policy output limit error, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("writer received partial output: %q", out.String())
	}

	err = p.SanitizeReaderToWriter(
		strings.NewReader(input),
		&out,
		SanitizeBudget{MaxOutputBytes: 0},
	)
	if err != nil {
		t.Fatalf("unexpected error with unlimited per-call budget: %v", err)
	}

	if got, want := p.Sanitize(input), string(mustSanitizeUnlimited(p, input)); got != want {
		t.Fatalf("Sanitize() changed under a policy budget: got %q, want %q", got, want)
	}
	if out := p.SanitizeReader(strings.NewReader(input)); out.Len() != 0 {
		t.Fatalf("SanitizeReader() did not apply the policy budget: %q", out.String())
	}
}

func mustSanitizeUnlimited(p *Policy, input string) []byte {
	var out bytes.Buffer
	if err := p.SanitizeReaderToWriter(
		strings.NewReader(input),
		&out,
		SanitizeBudget{},
	); err != nil {
		panic(err)
	}
	return out.Bytes()
}

func TestSanitizeReaderToWriterAcceptsBudgetAliases(t *testing.T) {
	p := UGCPolicy()
	input := `<p>Hello</p>`

	tests := []struct {
		name   string
		budget interface{}
	}{
		{"value budget", Budget{MaxNodes: 1}},
		{"pointer budget", &SanitizeBudget{MaxNodes: 1}},
		{"alias budget", Limits{Nodes: 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := p.SanitizeReaderToWriter(strings.NewReader(input), &out, tt.budget)
			if !errors.Is(err, ErrNodeLimitExceeded) {
				t.Fatalf("expected node limit error, got %v", err)
			}
			if out.Len() != 0 {
				t.Fatalf("writer received partial output: %q", out.String())
			}
		})
	}

	var out bytes.Buffer
	err := p.SanitizeReaderToWriter(strings.NewReader(input), &out, 0, 1, 0)
	if !errors.Is(err, ErrNodeLimitExceeded) {
		t.Fatalf("expected node limit error from numeric limits, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("writer received partial output: %q", out.String())
	}
}

type failingReader struct {
	r   io.Reader
	err error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.r == nil {
		return 0, r.err
	}
	n, err := r.r.Read(p)
	if err == io.EOF {
		r.r = nil
		return n, r.err
	}
	return n, err
}

type failingWriter struct {
	err error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	return 0, w.err
}
