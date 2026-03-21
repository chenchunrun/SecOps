package tools

import "errors"

var (
	ErrEmptyToolType       = errors.New("tool type cannot be empty")
	ErrToolNotFound        = errors.New("tool not found")
	ErrInvalidParams       = errors.New("invalid parameters")
	ErrExecutionFailed     = errors.New("tool execution failed")
	ErrCapabilityDenied    = errors.New("required capability denied")
	ErrResourceNotFound    = errors.New("resource not found")
	ErrTimeoutExceeded     = errors.New("execution timeout exceeded")
	ErrInvalidDateRange    = errors.New("invalid date range")
	ErrEmptyResult         = errors.New("no results found")
)
