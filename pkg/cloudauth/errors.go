package cloudauth

import (
	"errors"
	"fmt"
)

// ErrorCategory categorizes errors for handling and reporting.
type ErrorCategory string

const (
	// ErrCategoryAuth indicates an authentication or authorization failure.
	ErrCategoryAuth ErrorCategory = "auth"
	// ErrCategoryPermission indicates insufficient permissions.
	ErrCategoryPermission ErrorCategory = "permission"
	// ErrCategoryNetwork indicates a network-related failure.
	ErrCategoryNetwork ErrorCategory = "network"
	// ErrCategoryValidation indicates invalid input or configuration.
	ErrCategoryValidation ErrorCategory = "validation"
	// ErrCategoryNotFound indicates a resource was not found.
	ErrCategoryNotFound ErrorCategory = "not_found"
	// ErrCategoryConflict indicates a resource conflict (already exists).
	ErrCategoryConflict ErrorCategory = "conflict"
	// ErrCategoryRateLimit indicates rate limiting.
	ErrCategoryRateLimit ErrorCategory = "rate_limit"
	// ErrCategoryInternal indicates an internal error.
	ErrCategoryInternal ErrorCategory = "internal"
	// ErrCategoryTimeout indicates an operation timed out.
	ErrCategoryTimeout ErrorCategory = "timeout"
)

// CloudAuthError is a structured error with category and context.
type CloudAuthError struct {
	// Category classifies the error type.
	Category ErrorCategory

	// Message is a human-readable error message.
	Message string

	// Provider is the cloud provider where the error occurred.
	Provider CloudProvider

	// Operation is the operation that failed.
	Operation string

	// ResourceType is the type of resource involved.
	ResourceType string

	// ResourceID is the ID of the resource involved.
	ResourceID string

	// Cause is the underlying error.
	Cause error

	// Retryable indicates whether the operation can be retried.
	Retryable bool

	// Details contains additional error context.
	Details map[string]interface{}
}

// Error implements the error interface.
func (e *CloudAuthError) Error() string {
	msg := fmt.Sprintf("[%s] %s", e.Category, e.Message)
	if e.Provider != "" {
		msg = fmt.Sprintf("[%s:%s] %s", e.Provider, e.Category, e.Message)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

// Unwrap returns the underlying error.
func (e *CloudAuthError) Unwrap() error {
	return e.Cause
}

// Is checks if the target error matches this error's category.
func (e *CloudAuthError) Is(target error) bool {
	var caErr *CloudAuthError
	if errors.As(target, &caErr) {
		return e.Category == caErr.Category
	}
	return false
}

// NewError creates a new CloudAuthError.
func NewError(category ErrorCategory, message string) *CloudAuthError {
	return &CloudAuthError{
		Category: category,
		Message:  message,
		Details:  make(map[string]interface{}),
	}
}

// WithProvider sets the provider.
func (e *CloudAuthError) WithProvider(p CloudProvider) *CloudAuthError {
	e.Provider = p
	return e
}

// WithOperation sets the operation.
func (e *CloudAuthError) WithOperation(op string) *CloudAuthError {
	e.Operation = op
	return e
}

// WithResource sets the resource type and ID.
func (e *CloudAuthError) WithResource(resourceType, resourceID string) *CloudAuthError {
	e.ResourceType = resourceType
	e.ResourceID = resourceID
	return e
}

// WithCause sets the underlying error.
func (e *CloudAuthError) WithCause(err error) *CloudAuthError {
	e.Cause = err
	return e
}

// WithRetryable marks the error as retryable.
func (e *CloudAuthError) WithRetryable(retryable bool) *CloudAuthError {
	e.Retryable = retryable
	return e
}

// WithDetail adds a detail to the error.
func (e *CloudAuthError) WithDetail(key string, value interface{}) *CloudAuthError {
	e.Details[key] = value
	return e
}

// Convenience constructors for common error types

// ErrAuth creates an authentication error.
func ErrAuth(message string) *CloudAuthError {
	return NewError(ErrCategoryAuth, message)
}

// ErrPermission creates a permission error.
func ErrPermission(message string) *CloudAuthError {
	return NewError(ErrCategoryPermission, message)
}

// ErrNetwork creates a network error.
func ErrNetwork(message string) *CloudAuthError {
	return NewError(ErrCategoryNetwork, message).WithRetryable(true)
}

// ErrValidation creates a validation error.
func ErrValidation(message string) *CloudAuthError {
	return NewError(ErrCategoryValidation, message)
}

// ErrNotFound creates a not found error.
func ErrNotFound(resourceType, resourceID string) *CloudAuthError {
	return NewError(ErrCategoryNotFound, fmt.Sprintf("%s not found: %s", resourceType, resourceID)).
		WithResource(resourceType, resourceID)
}

// ErrConflict creates a conflict error.
func ErrConflict(resourceType, resourceID string) *CloudAuthError {
	return NewError(ErrCategoryConflict, fmt.Sprintf("%s already exists: %s", resourceType, resourceID)).
		WithResource(resourceType, resourceID)
}

// ErrRateLimit creates a rate limit error.
func ErrRateLimit(message string) *CloudAuthError {
	return NewError(ErrCategoryRateLimit, message).WithRetryable(true)
}

// ErrInternal creates an internal error.
func ErrInternal(message string) *CloudAuthError {
	return NewError(ErrCategoryInternal, message)
}

// ErrTimeout creates a timeout error.
func ErrTimeout(message string) *CloudAuthError {
	return NewError(ErrCategoryTimeout, message).WithRetryable(true)
}

// IsCategory checks if an error is of a specific category.
func IsCategory(err error, category ErrorCategory) bool {
	var caErr *CloudAuthError
	if errors.As(err, &caErr) {
		return caErr.Category == category
	}
	return false
}

// IsRetryable checks if an error is retryable.
func IsRetryable(err error) bool {
	var caErr *CloudAuthError
	if errors.As(err, &caErr) {
		return caErr.Retryable
	}
	return false
}

// GetErrorProvider extracts the provider from an error.
func GetErrorProvider(err error) CloudProvider {
	var caErr *CloudAuthError
	if errors.As(err, &caErr) {
		return caErr.Provider
	}
	return ""
}

// RollbackError represents an error during rollback with partial cleanup info.
type RollbackError struct {
	// OriginalError is the error that triggered rollback.
	OriginalError error

	// RollbackErrors are errors encountered during rollback.
	RollbackErrors []error

	// CleanedResources lists resources that were successfully cleaned up.
	CleanedResources []string

	// OrphanedResources lists resources that couldn't be cleaned up.
	OrphanedResources []string
}

// Error implements the error interface.
func (e *RollbackError) Error() string {
	msg := fmt.Sprintf("rollback failed after: %v", e.OriginalError)
	if len(e.OrphanedResources) > 0 {
		msg = fmt.Sprintf("%s; orphaned resources: %v", msg, e.OrphanedResources)
	}
	return msg
}

// Unwrap returns the original error.
func (e *RollbackError) Unwrap() error {
	return e.OriginalError
}

