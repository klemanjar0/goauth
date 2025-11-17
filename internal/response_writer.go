package internal

import (
	"encoding/json"
	"fmt"
	"net/http"

	"goauth/internal/logger"
)

// ResponseWriter provides a fluent API for building and sending HTTP responses
type ResponseWriter struct {
	w          http.ResponseWriter
	statusCode int
	data       any
	err        error
	headers    map[string]string
	message    string
	sent       bool
}

// ErrorResponse represents a standardized error response structure
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

// SuccessResponse represents a standardized success response structure
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

// NewResponseWriter creates a new response writer instance
func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		w:          w,
		statusCode: http.StatusOK,
		headers:    make(map[string]string),
		sent:       false,
	}
}

// Status sets the HTTP status code for the response
func (rw *ResponseWriter) Status(code int) *ResponseWriter {
	if rw.sent {
		logger.Warn().Msg("attempted to set status after response was sent")
		return rw
	}
	rw.statusCode = code
	return rw
}

// Json sets the response data to be encoded as JSON
func (rw *ResponseWriter) Json(data any) *ResponseWriter {
	if rw.sent {
		logger.Warn().Msg("attempted to set JSON data after response was sent")
		return rw
	}
	rw.data = data
	rw.headers["Content-Type"] = "application/json"
	return rw
}

// Error sets an error for the response
func (rw *ResponseWriter) Error(err error) *ResponseWriter {
	if rw.sent {
		logger.Warn().Msg("attempted to set error after response was sent")
		return rw
	}
	rw.err = err
	rw.headers["Content-Type"] = "application/json"
	return rw
}

// Message sets a custom message for the response
func (rw *ResponseWriter) Message(msg string) *ResponseWriter {
	if rw.sent {
		logger.Warn().Msg("attempted to set message after response was sent")
		return rw
	}
	rw.message = msg
	return rw
}

// Header sets a custom header for the response
func (rw *ResponseWriter) Header(key, value string) *ResponseWriter {
	if rw.sent {
		logger.Warn().Msg("attempted to set header after response was sent")
		return rw
	}
	rw.headers[key] = value
	return rw
}

// Send finalizes and sends the HTTP response
func (rw *ResponseWriter) Send() {
	if rw.sent {
		logger.Warn().Msg("attempted to send response multiple times")
		return
	}
	rw.sent = true

	// Set all custom headers
	for key, value := range rw.headers {
		rw.w.Header().Set(key, value)
	}

	// Handle error responses
	if rw.err != nil {
		rw.sendErrorResponse()
		return
	}

	// Handle success responses
	rw.sendSuccessResponse()
}

// sendErrorResponse sends a standardized error response
func (rw *ResponseWriter) sendErrorResponse() {
	// Default to 500 if status code is 2xx
	if rw.statusCode >= 200 && rw.statusCode < 300 {
		rw.statusCode = http.StatusInternalServerError
	}

	errorMsg := rw.err.Error()

	// Create error response
	errResp := ErrorResponse{
		Error:   errorMsg,
		Message: rw.message,
		Code:    rw.statusCode,
	}

	// Log the error
	logEvent := logger.Error().
		Err(rw.err).
		Int("status", rw.statusCode)

	if rw.message != "" {
		logEvent.Str("message", rw.message)
	}

	logEvent.Msg("HTTP error response")

	// Write response
	rw.w.WriteHeader(rw.statusCode)

	if err := json.NewEncoder(rw.w).Encode(errResp); err != nil {
		logger.Error().
			Err(err).
			Msg("failed to encode error response")
		// Fallback to plain text
		_, _ = fmt.Fprintf(rw.w, `{"error":"internal server error","code":%d}`, http.StatusInternalServerError)
	}
}

// sendSuccessResponse sends a standardized success response
func (rw *ResponseWriter) sendSuccessResponse() {
	// Ensure Content-Type is set
	if rw.headers["Content-Type"] == "" {
		rw.w.Header().Set("Content-Type", "application/json")
	}

	rw.w.WriteHeader(rw.statusCode)

	// If data is set, send it directly
	if rw.data != nil {
		if err := json.NewEncoder(rw.w).Encode(rw.data); err != nil {
			logger.Error().
				Err(err).
				Int("status", rw.statusCode).
				Msg("failed to encode success response")
			return
		}
		return
	}

	// If only message is set, send a simple success response
	if rw.message != "" {
		resp := SuccessResponse{
			Success: true,
			Message: rw.message,
		}
		if err := json.NewEncoder(rw.w).Encode(resp); err != nil {
			logger.Error().
				Err(err).
				Msg("failed to encode message response")
		}
		return
	}

	// Send empty JSON object if nothing is set
	_, _ = rw.w.Write([]byte("{}"))
}

// Text sends a plain text response
func (rw *ResponseWriter) Text(text string) *ResponseWriter {
	if rw.sent {
		logger.Warn().Msg("attempted to set text after response was sent")
		return rw
	}
	rw.message = text
	rw.headers["Content-Type"] = "text/plain; charset=utf-8"
	return rw
}

// SendText is a convenience method to send plain text responses
func (rw *ResponseWriter) SendText() {
	if rw.sent {
		logger.Warn().Msg("attempted to send response multiple times")
		return
	}
	rw.sent = true

	for key, value := range rw.headers {
		rw.w.Header().Set(key, value)
	}

	rw.w.WriteHeader(rw.statusCode)

	if rw.message != "" {
		_, _ = rw.w.Write([]byte(rw.message))
	}
}

// NoContent sends a 204 No Content response
func (rw *ResponseWriter) NoContent() {
	if rw.sent {
		logger.Warn().Msg("attempted to send response multiple times")
		return
	}
	rw.sent = true
	rw.w.WriteHeader(http.StatusNoContent)
}

// Redirect sends a redirect response
func (rw *ResponseWriter) Redirect(url string, permanent bool) {
	if rw.sent {
		logger.Warn().Msg("attempted to send response multiple times")
		return
	}
	rw.sent = true

	code := http.StatusFound
	if permanent {
		code = http.StatusMovedPermanently
	}

	http.Redirect(rw.w, &http.Request{}, url, code)
}

// Helper functions for common response patterns

// OK sends a 200 OK response with optional data
func (rw *ResponseWriter) OK(data any) {
	rw.Status(http.StatusOK).Json(data).Send()
}

// Created sends a 201 Created response with optional data
func (rw *ResponseWriter) Created(data any) {
	rw.Status(http.StatusCreated).Json(data).Send()
}

// BadRequest sends a 400 Bad Request error response
func (rw *ResponseWriter) BadRequest(err error) {
	rw.Status(http.StatusBadRequest).Error(err).Send()
}

// Unauthorized sends a 401 Unauthorized error response
func (rw *ResponseWriter) Unauthorized(err error) {
	rw.Status(http.StatusUnauthorized).Error(err).Send()
}

// Forbidden sends a 403 Forbidden error response
func (rw *ResponseWriter) Forbidden(err error) {
	rw.Status(http.StatusForbidden).Error(err).Send()
}

// NotFound sends a 404 Not Found error response
func (rw *ResponseWriter) NotFound(err error) {
	rw.Status(http.StatusNotFound).Error(err).Send()
}

// Conflict sends a 409 Conflict error response
func (rw *ResponseWriter) Conflict(err error) {
	rw.Status(http.StatusConflict).Error(err).Send()
}

// InternalError sends a 500 Internal Server Error response
func (rw *ResponseWriter) InternalError(err error) {
	rw.Status(http.StatusInternalServerError).Error(err).Send()
}

// Package-level helper functions

// Respond creates a new ResponseWriter instance
func Respond(w http.ResponseWriter) *ResponseWriter {
	return NewResponseWriter(w)
}

// JSON is a convenience function to send a JSON response
func JSON(w http.ResponseWriter, statusCode int, data any) {
	NewResponseWriter(w).Status(statusCode).Json(data).Send()
}

// JSONError is a convenience function to send a JSON error response
func JSONError(w http.ResponseWriter, statusCode int, err error) {
	NewResponseWriter(w).Status(statusCode).Error(err).Send()
}

// JSONMessage is a convenience function to send a JSON response with a message
func JSONMessage(w http.ResponseWriter, statusCode int, message string) {
	NewResponseWriter(w).Status(statusCode).Message(message).Send()
}
