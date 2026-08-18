package storage

import "errors"

// Typed sentinel error constructors. Use these (not bare errors.New) so callers
// can distinguish validation / conflict / not-found via errors.As on the type.
type ErrValidationT string

func (e ErrValidationT) Error() string { return string(e) }
func (e ErrValidationT) Is(target error) bool {
	_, ok := target.(ErrValidationT)
	return ok
}

type ErrConflictT string

func (e ErrConflictT) Error() string { return string(e) }
func (e ErrConflictT) Is(target error) bool {
	_, ok := target.(ErrConflictT)
	return ok
}

type ErrNotFoundT string

func (e ErrNotFoundT) Error() string { return string(e) }
func (e ErrNotFoundT) Is(target error) bool {
	_, ok := target.(ErrNotFoundT)
	return ok
}

// AsNotFound returns true if err is an ErrNotFoundT.
func AsNotFound(err error) bool {
	var n ErrNotFoundT
	return errors.As(err, &n)
}
func AsConflict(err error) bool {
	var c ErrConflictT
	return errors.As(err, &c)
}
func AsValidation(err error) bool {
	var v ErrValidationT
	return errors.As(err, &v)
}
