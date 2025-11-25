package internal

import (
	"encoding/json"
	"fmt"
	"net/http"

	"goauth/internal/logger"
)

type ResponseWriter struct {
	w          http.ResponseWriter
	statusCode int
	data       any
	err        error
	headers    map[string]string
	message    string
	sent       bool
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		w:          w,
		statusCode: http.StatusOK,
		headers:    make(map[string]string),
		sent:       false,
	}
}

func (rw *ResponseWriter) Status(code int) *ResponseWriter {
	if rw.sent {
		logger.Warn().Msg("attempted to set status after response was sent")
		return rw
	}
	rw.statusCode = code
	return rw
}

func (rw *ResponseWriter) Json(data any) *ResponseWriter {
	if rw.sent {
		logger.Warn().Msg("attempted to set JSON data after response was sent")
		return rw
	}
	rw.data = data
	rw.headers["Content-Type"] = "application/json"
	return rw
}

func (rw *ResponseWriter) Error(err error) *ResponseWriter {
	if rw.sent {
		logger.Warn().Msg("attempted to set error after response was sent")
		return rw
	}
	rw.err = err
	rw.headers["Content-Type"] = "application/json"
	return rw
}

func (rw *ResponseWriter) Message(msg string) *ResponseWriter {
	if rw.sent {
		logger.Warn().Msg("attempted to set message after response was sent")
		return rw
	}
	rw.message = msg
	return rw
}

func (rw *ResponseWriter) Header(key, value string) *ResponseWriter {
	if rw.sent {
		logger.Warn().Msg("attempted to set header after response was sent")
		return rw
	}
	rw.headers[key] = value
	return rw
}

func (rw *ResponseWriter) Send() {
	if rw.sent {
		logger.Warn().Msg("attempted to send response multiple times")
		return
	}
	rw.sent = true

	for key, value := range rw.headers {
		rw.w.Header().Set(key, value)
	}

	if rw.err != nil {
		rw.sendErrorResponse()
		return
	}

	rw.sendSuccessResponse()
}

func (rw *ResponseWriter) sendErrorResponse() {
	if rw.statusCode >= 200 && rw.statusCode < 300 {
		rw.statusCode = http.StatusInternalServerError
	}

	errorMsg := rw.err.Error()

	errResp := ErrorResponse{
		Error:   errorMsg,
		Message: rw.message,
		Code:    rw.statusCode,
	}

	logEvent := logger.Error().
		Err(rw.err).
		Int("status", rw.statusCode)

	if rw.message != "" {
		logEvent.Str("message", rw.message)
	}

	logEvent.Msg("HTTP error response")

	rw.w.WriteHeader(rw.statusCode)

	if err := json.NewEncoder(rw.w).Encode(errResp); err != nil {
		logger.Error().
			Err(err).
			Msg("failed to encode error response")
		_, _ = fmt.Fprintf(rw.w, `{"error":"internal server error","code":%d}`, http.StatusInternalServerError)
	}
}

func (rw *ResponseWriter) sendSuccessResponse() {
	if rw.headers["Content-Type"] == "" {
		rw.w.Header().Set("Content-Type", "application/json")
	}

	rw.w.WriteHeader(rw.statusCode)

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

	_, _ = rw.w.Write([]byte("{}"))
}

func (rw *ResponseWriter) Text(text string) *ResponseWriter {
	if rw.sent {
		logger.Warn().Msg("attempted to set text after response was sent")
		return rw
	}
	rw.message = text
	rw.headers["Content-Type"] = "text/plain; charset=utf-8"
	return rw
}

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

func (rw *ResponseWriter) NoContent() {
	if rw.sent {
		logger.Warn().Msg("attempted to send response multiple times")
		return
	}
	rw.sent = true
	rw.w.WriteHeader(http.StatusNoContent)
}

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

func (rw *ResponseWriter) OK(data any) {
	rw.Status(http.StatusOK).Json(data).Send()
}

func (rw *ResponseWriter) Created(data any) {
	rw.Status(http.StatusCreated).Json(data).Send()
}

func (rw *ResponseWriter) BadRequest(err error) {
	rw.Status(http.StatusBadRequest).Error(err).Send()
}

func (rw *ResponseWriter) Unauthorized(err error) {
	rw.Status(http.StatusUnauthorized).Error(err).Send()
}

func (rw *ResponseWriter) Forbidden(err error) {
	rw.Status(http.StatusForbidden).Error(err).Send()
}

func (rw *ResponseWriter) NotFound(err error) {
	rw.Status(http.StatusNotFound).Error(err).Send()
}

func (rw *ResponseWriter) Conflict(err error) {
	rw.Status(http.StatusConflict).Error(err).Send()
}

func (rw *ResponseWriter) InternalError(err error) {
	rw.Status(http.StatusInternalServerError).Error(err).Send()
}

func Respond(w http.ResponseWriter) *ResponseWriter {
	return NewResponseWriter(w)
}

func JSON(w http.ResponseWriter, statusCode int, data any) {
	NewResponseWriter(w).Status(statusCode).Json(data).Send()
}

func JSONError(w http.ResponseWriter, statusCode int, err error) {
	NewResponseWriter(w).Status(statusCode).Error(err).Send()
}

func JSONMessage(w http.ResponseWriter, statusCode int, message string) {
	NewResponseWriter(w).Status(statusCode).Message(message).Send()
}
