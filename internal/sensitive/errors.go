// Package sensitive implements pre-ingestion sensitive information removal.
package sensitive

import "errors"

// Error deliberately contains no source text or underlying matcher diagnostics.
type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }

func Failure(code string) error { return &Error{Code: code} }

func Reason(err error) string {
	var failure *Error
	if errors.As(err, &failure) {
		return failure.Code
	}
	return ""
}
