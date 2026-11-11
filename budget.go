package bluemonday

import (
	"errors"
	"fmt"
	"io"
	"math"
)

// BudgetKind identifies which sanitization budget was exceeded.
type BudgetKind uint8

const (
	// InputBudget is the budget for bytes read from the input reader.
	InputBudget BudgetKind = iota + 1
	// NodeBudget is the budget for HTML tokens processed by the sanitizer.
	NodeBudget
	// OutputBudget is the budget for bytes emitted by the sanitizer.
	OutputBudget
)

func (k BudgetKind) String() string {
	switch k {
	case InputBudget:
		return "input"
	case NodeBudget:
		return "node"
	case OutputBudget:
		return "output"
	default:
		return "unknown"
	}
}

var (
	// ErrBudgetExceeded matches any of the individual budget errors below.
	ErrBudgetExceeded = errors.New("bluemonday: budget exceeded")
	// ErrInputLimitExceeded is returned when the configured input budget is
	// exceeded.
	ErrInputLimitExceeded = errors.New("bluemonday: input budget exceeded")
	// ErrNodeLimitExceeded is returned when the configured node budget is
	// exceeded.
	ErrNodeLimitExceeded = errors.New("bluemonday: node budget exceeded")
	// ErrOutputLimitExceeded is returned when the configured output budget is
	// exceeded.
	ErrOutputLimitExceeded = errors.New("bluemonday: output budget exceeded")
	// ErrReadFailed is returned when the input reader fails.
	ErrReadFailed = errors.New("bluemonday: read failed")
	// ErrWriteFailed is returned when the destination writer fails.
	ErrWriteFailed = errors.New("bluemonday: write failed")

	// Aliases for the budget error names that are used in the wild.
	ErrInputBudgetExceeded  = ErrInputLimitExceeded
	ErrNodeBudgetExceeded   = ErrNodeLimitExceeded
	ErrOutputBudgetExceeded = ErrOutputLimitExceeded
	ErrLimitExceeded        = ErrBudgetExceeded
	ErrBudget               = ErrBudgetExceeded
	ErrInputLimit           = ErrInputLimitExceeded
	ErrNodeLimit            = ErrNodeLimitExceeded
	ErrOutputLimit          = ErrOutputLimitExceeded
	ErrInputBudget          = ErrInputLimitExceeded
	ErrNodeBudget           = ErrNodeLimitExceeded
	ErrOutputBudget         = ErrOutputLimitExceeded
	ErrReader               = ErrReadFailed
	ErrWriter               = ErrWriteFailed
	ErrRead                 = ErrReadFailed
	ErrWrite                = ErrWriteFailed
	ErrInputTooLarge        = ErrInputLimitExceeded
	ErrTooManyNodes         = ErrNodeLimitExceeded
	ErrOutputTooLarge       = ErrOutputLimitExceeded
)

// LimitError describes a sanitization budget that was exceeded.
type LimitError struct {
	Budget BudgetKind
	Limit  int64
	Actual int64
}

// BudgetError is an alias for LimitError.
type BudgetError = LimitError

// BudgetExceededError is an alias for LimitError.
type BudgetExceededError = LimitError

// SanitizeLimitError is an alias for LimitError.
type SanitizeLimitError = LimitError

func (e *LimitError) Error() string {
	return fmt.Sprintf(
		"bluemonday: %s budget exceeded (limit %d, actual %d)",
		e.Budget,
		e.Limit,
		e.Actual,
	)
}

// Unwrap returns the sentinel for the individual budget that was exceeded.
func (e *LimitError) Unwrap() error {
	switch e.Budget {
	case InputBudget:
		return ErrInputLimitExceeded
	case NodeBudget:
		return ErrNodeLimitExceeded
	case OutputBudget:
		return ErrOutputLimitExceeded
	default:
		return nil
	}
}

// Is supports errors.Is checks against the individual and aggregate budget
// errors.
func (e *LimitError) Is(target error) bool {
	switch target {
	case ErrBudgetExceeded, ErrLimitExceeded:
		return true
	case ErrInputLimitExceeded, ErrInputBudgetExceeded:
		return e.Budget == InputBudget
	case ErrNodeLimitExceeded, ErrNodeBudgetExceeded:
		return e.Budget == NodeBudget
	case ErrOutputLimitExceeded, ErrOutputBudgetExceeded:
		return e.Budget == OutputBudget
	default:
		return false
	}
}

// ReadError describes a failure while reading the input stream.
type ReadError struct {
	Err error
}

func (e *ReadError) Error() string {
	return fmt.Sprintf("%s: %v", ErrReadFailed, e.Err)
}

// Unwrap exposes the underlying reader error to errors.Is and errors.As.
func (e *ReadError) Unwrap() error {
	return e.Err
}

// Is allows errors.Is(err, ErrReadFailed).
func (e *ReadError) Is(target error) bool {
	return target == ErrReadFailed || target == ErrReader
}

// WriteError describes a failure while writing the sanitized result.
type WriteError struct {
	Err error
}

func (e *WriteError) Error() string {
	return fmt.Sprintf("%s: %v", ErrWriteFailed, e.Err)
}

// Unwrap exposes the underlying writer error to errors.Is and errors.As.
func (e *WriteError) Unwrap() error {
	return e.Err
}

// Is allows errors.Is(err, ErrWriteFailed).
func (e *WriteError) Is(target error) bool {
	return target == ErrWriteFailed || target == ErrWriter
}

// SanitizeBudget bounds the work performed by SanitizeReaderToWriter.
//
// A zero or negative value means that the corresponding budget is unlimited.
// The zero value of SanitizeBudget therefore preserves the historical
// unlimited behavior.
//
// Budgets are measured against the data that is actually processed rather than
// only the source text:
//
//   - MaxInputBytes counts bytes read from the input reader.
//   - MaxNodes counts HTML tokens processed, including text, comments and
//     doctype tokens produced after entity expansion.
//   - MaxOutputBytes counts the sanitized bytes emitted after URL rewriting,
//     style sanitization and HTML escaping.
//
// The aliases below allow the budget to be configured with either the
// Max*-prefixed names or the shorter Input/Nodes/Output names. Max*-prefixed
// fields take precedence when more than one alias for the same budget is set.
type SanitizeBudget struct {
	MaxInputBytes  int64
	MaxNodes       int64
	MaxOutputBytes int64

	Input  int64
	Nodes  int64
	Output int64

	InputBytes  int64
	MaxInput    int64
	MaxTokens   int64
	MaxOutput   int64
	OutputBytes int64

	InputLimit  int64
	NodeLimit   int64
	OutputLimit int64

	InputBudget  int64
	NodeBudget   int64
	OutputBudget int64

	MaxInputSize  int64
	MaxNodeCount  int64
	MaxOutputSize int64
}

// Budget is an alias for SanitizeBudget.
type Budget = SanitizeBudget

// Limits is an alias for SanitizeBudget.
type Limits = SanitizeBudget

// SanitizeLimits is an alias for SanitizeBudget.
type SanitizeLimits = SanitizeBudget

// SanitizationLimits is an alias for SanitizeBudget.
type SanitizationLimits = SanitizeBudget

// SanitizeOptions is an alias for SanitizeBudget.
type SanitizeOptions = SanitizeBudget

// BudgetOptions is an alias for SanitizeBudget.
type BudgetOptions = SanitizeBudget

// Limit is an alias for SanitizeBudget.
type Limit = SanitizeBudget

// NewBudget returns a budget with the supplied limits. Zero or negative
// values leave the corresponding budget unlimited.
func NewBudget(inputBytes, maxNodes, outputBytes int64) SanitizeBudget {
	return SanitizeBudget{
		MaxInputBytes:  inputBytes,
		MaxNodes:       maxNodes,
		MaxOutputBytes: outputBytes,
	}
}

// NewSanitizeBudget returns a budget with the supplied limits.
func NewSanitizeBudget(inputBytes, maxNodes, outputBytes int64) SanitizeBudget {
	return NewBudget(inputBytes, maxNodes, outputBytes)
}

// NewLimits returns a budget with the supplied limits.
func NewLimits(inputBytes, maxNodes, outputBytes int64) SanitizeBudget {
	return NewBudget(inputBytes, maxNodes, outputBytes)
}

func firstPositive(values ...int64) int64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func (b SanitizeBudget) inputLimit() int64 {
	return firstPositive(
		b.MaxInputBytes,
		b.InputLimit,
		b.InputBudget,
		b.InputBytes,
		b.Input,
		b.MaxInput,
		b.MaxInputSize,
	)
}

func (b SanitizeBudget) nodeLimit() int64 {
	return firstPositive(
		b.MaxNodes,
		b.NodeLimit,
		b.NodeBudget,
		b.MaxTokens,
		b.Nodes,
		b.MaxNodeCount,
	)
}

func (b SanitizeBudget) outputLimit() int64 {
	return firstPositive(
		b.MaxOutputBytes,
		b.OutputLimit,
		b.OutputBudget,
		b.OutputBytes,
		b.Output,
		b.MaxOutput,
		b.MaxOutputSize,
	)
}

func budgetFromArgs(defaultBudget SanitizeBudget, args []interface{}) (SanitizeBudget, error) {
	switch len(args) {
	case 0:
		return defaultBudget, nil
	case 1:
		switch budget := args[0].(type) {
		case nil:
			return SanitizeBudget{}, nil
		case SanitizeBudget:
			return budget, nil
		case *SanitizeBudget:
			if budget == nil {
				return SanitizeBudget{}, nil
			}
			return *budget, nil
		default:
			if limit, ok := numericInt64(args[0]); ok {
				return SanitizeBudget{MaxInputBytes: limit}, nil
			}
			return SanitizeBudget{}, fmt.Errorf(
				"bluemonday: unsupported budget argument %T",
				args[0],
			)
		}
	case 3:
		input, ok := numericInt64(args[0])
		if !ok {
			return SanitizeBudget{}, fmt.Errorf(
				"bluemonday: invalid input budget %T",
				args[0],
			)
		}
		nodes, ok := numericInt64(args[1])
		if !ok {
			return SanitizeBudget{}, fmt.Errorf(
				"bluemonday: invalid node budget %T",
				args[1],
			)
		}
		output, ok := numericInt64(args[2])
		if !ok {
			return SanitizeBudget{}, fmt.Errorf(
				"bluemonday: invalid output budget %T",
				args[2],
			)
		}
		return SanitizeBudget{
			MaxInputBytes:  input,
			MaxNodes:       nodes,
			MaxOutputBytes: output,
		}, nil
	default:
		return SanitizeBudget{}, fmt.Errorf(
			"bluemonday: expected a budget or three integer limits, got %d arguments",
			len(args),
		)
	}
}

func numericInt64(value interface{}) (int64, bool) {
	switch n := value.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		if uint64(n) > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		if uint64(n) > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	default:
		return 0, false
	}
}

type budgetReader struct {
	reader io.Reader
	limit  int64
	used   int64
}

func (r *budgetReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if r.limit <= 0 {
		n, err := r.reader.Read(p)
		r.used += int64(n)
		return n, err
	}

	remaining := r.limit - r.used
	if remaining <= 0 {
		// Probe for one more byte so that input of exactly the configured
		// size succeeds while any additional data is reported as an overrun.
		n, err := r.reader.Read(p[:1])
		if n > 0 {
			r.used += int64(n)
			return 0, &LimitError{
				Budget: InputBudget,
				Limit:  r.limit,
				Actual: r.used,
			}
		}
		return 0, err
	}

	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := r.reader.Read(p)
	r.used += int64(n)
	return n, err
}

type budgetWriter struct {
	writer io.Writer
	limit  int64
	used   int64
}

func (w *budgetWriter) Write(p []byte) (int, error) {
	if w.limit > 0 && int64(len(p)) > w.limit-w.used {
		return 0, &LimitError{
			Budget: OutputBudget,
			Limit:  w.limit,
			Actual: w.used + int64(len(p)),
		}
	}

	n, err := w.writer.Write(p)
	w.used += int64(n)
	return n, err
}

func (w *budgetWriter) WriteString(s string) (int, error) {
	if w.limit > 0 && int64(len(s)) > w.limit-w.used {
		return 0, &LimitError{
			Budget: OutputBudget,
			Limit:  w.limit,
			Actual: w.used + int64(len(s)),
		}
	}

	if sw, ok := w.writer.(io.StringWriter); ok {
		n, err := sw.WriteString(s)
		w.used += int64(n)
		return n, err
	}

	return w.Write([]byte(s))
}

type nodeBudget struct {
	limit int64
	used  int64
}

func (b *nodeBudget) next() error {
	b.used++
	if b.limit > 0 && b.used > b.limit {
		return &LimitError{
			Budget: NodeBudget,
			Limit:  b.limit,
			Actual: b.used,
		}
	}
	return nil
}

// WithBudget sets the budgets used by SanitizeReaderToWriter and returns the
// policy to allow chaining. A zero budget is unlimited.
func (p *Policy) WithBudget(budget interface{}) *Policy {
	parsed, err := budgetFromArgs(SanitizeBudget{}, []interface{}{budget})
	if err == nil {
		p.sanitizeBudget = parsed
	}
	return p
}

// WithLimits is an alias for WithBudget.
func (p *Policy) WithLimits(limits interface{}) *Policy {
	return p.WithBudget(limits)
}

// SetBudget is an alias for WithBudget.
func (p *Policy) SetBudget(budget interface{}) *Policy {
	return p.WithBudget(budget)
}

// SetLimits is an alias for WithBudget.
func (p *Policy) SetLimits(limits interface{}) *Policy {
	return p.WithBudget(limits)
}

// SetSanitizeBudget is an alias for WithBudget.
func (p *Policy) SetSanitizeBudget(budget interface{}) *Policy {
	return p.WithBudget(budget)
}

// SetMaxInputBytes sets the input budget in bytes.
func (p *Policy) SetMaxInputBytes(limit int64) *Policy {
	p.sanitizeBudget.MaxInputBytes = limit
	return p
}

// WithMaxInputBytes sets the input budget in bytes.
func (p *Policy) WithMaxInputBytes(limit int64) *Policy {
	return p.SetMaxInputBytes(limit)
}

// SetInputBudget sets the input budget in bytes.
func (p *Policy) SetInputBudget(limit int64) *Policy {
	return p.SetMaxInputBytes(limit)
}

// WithInputBudget sets the input budget in bytes.
func (p *Policy) WithInputBudget(limit int64) *Policy {
	return p.SetMaxInputBytes(limit)
}

// SetInputLimit sets the input budget in bytes.
func (p *Policy) SetInputLimit(limit int64) *Policy {
	return p.SetMaxInputBytes(limit)
}

// SetMaxInput sets the input budget in bytes.
func (p *Policy) SetMaxInput(limit int64) *Policy {
	return p.SetMaxInputBytes(limit)
}

// SetMaxNodes sets the node budget in tokens.
func (p *Policy) SetMaxNodes(limit int64) *Policy {
	p.sanitizeBudget.MaxNodes = limit
	return p
}

// WithMaxNodes sets the node budget in tokens.
func (p *Policy) WithMaxNodes(limit int64) *Policy {
	return p.SetMaxNodes(limit)
}

// SetMaxTokens sets the node budget in tokens.
func (p *Policy) SetMaxTokens(limit int64) *Policy {
	return p.SetMaxNodes(limit)
}

// WithMaxTokens sets the node budget in tokens.
func (p *Policy) WithMaxTokens(limit int64) *Policy {
	return p.SetMaxNodes(limit)
}

// SetNodeBudget sets the node budget in tokens.
func (p *Policy) SetNodeBudget(limit int64) *Policy {
	return p.SetMaxNodes(limit)
}

// SetNodeLimit sets the node budget in tokens.
func (p *Policy) SetNodeLimit(limit int64) *Policy {
	return p.SetMaxNodes(limit)
}

// SetMaxOutputBytes sets the output budget in bytes.
func (p *Policy) SetMaxOutputBytes(limit int64) *Policy {
	p.sanitizeBudget.MaxOutputBytes = limit
	return p
}

// WithMaxOutputBytes sets the output budget in bytes.
func (p *Policy) WithMaxOutputBytes(limit int64) *Policy {
	return p.SetMaxOutputBytes(limit)
}

// SetOutputBudget sets the output budget in bytes.
func (p *Policy) SetOutputBudget(limit int64) *Policy {
	return p.SetMaxOutputBytes(limit)
}

// WithOutputBudget sets the output budget in bytes.
func (p *Policy) WithOutputBudget(limit int64) *Policy {
	return p.SetMaxOutputBytes(limit)
}

// SetOutputLimit sets the output budget in bytes.
func (p *Policy) SetOutputLimit(limit int64) *Policy {
	return p.SetMaxOutputBytes(limit)
}

// SetMaxOutput sets the output budget in bytes.
func (p *Policy) SetMaxOutput(limit int64) *Policy {
	return p.SetMaxOutputBytes(limit)
}

// MaxInputBytes sets the input budget in bytes.
func (p *Policy) MaxInputBytes(limit int64) *Policy {
	return p.SetMaxInputBytes(limit)
}

// MaxInput sets the input budget in bytes.
func (p *Policy) MaxInput(limit int64) *Policy {
	return p.MaxInputBytes(limit)
}

// MaxTokens sets the node budget in tokens.
func (p *Policy) MaxTokens(limit int64) *Policy {
	return p.SetMaxNodes(limit)
}

// MaxNodes sets the node budget in tokens.
func (p *Policy) MaxNodes(limit int64) *Policy {
	return p.SetMaxNodes(limit)
}

// MaxOutputBytes sets the output budget in bytes.
func (p *Policy) MaxOutputBytes(limit int64) *Policy {
	return p.SetMaxOutputBytes(limit)
}

// MaxOutput sets the output budget in bytes.
func (p *Policy) MaxOutput(limit int64) *Policy {
	return p.MaxOutputBytes(limit)
}

// SanitizeReaderToWriterWithBudget is a typed alternative to
// SanitizeReaderToWriter for callers that prefer not to use variadic options.
func (p *Policy) SanitizeReaderToWriterWithBudget(
	r io.Reader,
	w io.Writer,
	budget interface{},
) error {
	parsed, err := budgetFromArgs(SanitizeBudget{}, []interface{}{budget})
	if err != nil {
		return err
	}
	return p.sanitizeWithBudget(r, w, parsed)
}

// SanitizeReaderToWriterWithLimits is a typed alternative to
// SanitizeReaderToWriter.
func (p *Policy) SanitizeReaderToWriterWithLimits(
	r io.Reader,
	w io.Writer,
	limits interface{},
) error {
	return p.SanitizeReaderToWriterWithBudget(r, w, limits)
}

// SanitizeReaderToWriterWithBudgetPtr accepts a pointer budget.
func (p *Policy) SanitizeReaderToWriterWithBudgetPtr(
	r io.Reader,
	w io.Writer,
	budget *SanitizeBudget,
) error {
	if budget == nil {
		return p.sanitizeWithBudget(r, w, SanitizeBudget{})
	}
	return p.sanitizeWithBudget(r, w, *budget)
}
