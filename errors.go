package nes

import "fmt"

type ErrorType int

const (
	ErrConfiguration ErrorType = iota
	ErrDocker
	ErrContainer
	ErrNetwork
)

// Custom error structure
type Error struct {
	Type    ErrorType
	Message string
	Err     error
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %v", e.Message, e.Err)
}

func NewError(errType ErrorType, message string, err error) *Error {
	return &Error{
		Type:    errType,
		Message: message,
		Err:     err,
	}
}
