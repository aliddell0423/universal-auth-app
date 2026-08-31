package model

// ApiError is the structured error envelope returned by Universal Auth services.
type ApiError struct {
	Code      string `json:"code"`
	Stage     string `json:"stage"`
	Message   string `json:"message"`
	TraceID   string `json:"trace_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Retryable bool   `json:"retryable"`
	Action    string `json:"action"`
}

func NewApiError(code, stage, message, action string, retryable bool) ApiError {
	return ApiError{
		Code:      code,
		Stage:     stage,
		Message:   message,
		Retryable: retryable,
		Action:    action,
	}
}
