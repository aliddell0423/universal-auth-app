package apierror

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Error is the cross-component structured error envelope used by Universal Auth.
type Error struct {
	Code      string `json:"code"`
	Stage     string `json:"stage"`
	Message   string `json:"message"`
	TraceID   string `json:"trace_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Retryable bool   `json:"retryable"`
	Action    string `json:"action"`

	// StatusCode is the raw HTTP status; it is not serialised.
	StatusCode int `json:"-"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// FromResponse decodes an ApiError from an HTTP response body. If the body
// cannot be parsed, it builds a generic Error from the status and raw body.
func FromResponse(resp *http.Response, stage, fallbackCode string) *Error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	var apiErr Error
	if err := json.Unmarshal(body, &apiErr); err == nil && apiErr.Code != "" {
		apiErr.StatusCode = resp.StatusCode
		if apiErr.Stage == "" {
			apiErr.Stage = stage
		}
		return &apiErr
	}

	return &Error{
		Code:       fallbackCode,
		Stage:      stage,
		Message:    "Request failed.",
		Retryable:  false,
		Action:     "Check service logs and run 'authctl doctor'.",
		StatusCode: resp.StatusCode,
	}
}

// New builds a typed Error from explicit fields.
func New(code, stage, message, action string, retryable bool) *Error {
	return &Error{
		Code:      code,
		Stage:     stage,
		Message:   message,
		Action:    action,
		Retryable: retryable,
	}
}
