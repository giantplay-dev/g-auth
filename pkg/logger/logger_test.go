package logger

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLogger_Development(t *testing.T) {
	logger, err := NewLogger("development")

	assert.NoError(t, err)
	assert.NotNil(t, logger)
}

func TestNewLogger_Production(t *testing.T) {
	logger, err := NewLogger("production")

	assert.NoError(t, err)
	assert.NotNil(t, logger)
}

func TestLogger_Info(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	// Should not panic
	assert.NotPanics(t, func() {
		logger.Info("test message", "key", "value")
	})
}

func TestLogger_Error(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	// Should not panic
	assert.NotPanics(t, func() {
		logger.Error("test error", "key", "value")
	})
}

func TestLogger_Warn(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	// Should not panic
	assert.NotPanics(t, func() {
		logger.Warn("test warning", "key", "value")
	})
}

func TestLogger_Debug(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	// Should not panic
	assert.NotPanics(t, func() {
		logger.Debug("test debug", "key", "value")
	})
}

func TestLogger_With(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	newLogger := logger.With("extra_key", "extra_value")

	assert.NotNil(t, newLogger)
	assert.NotPanics(t, func() {
		newLogger.Info("test with extra field")
	})
}

func TestLogger_WithTraceID_WithTraceIDInContext(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	ctx := context.WithValue(context.Background(), "trace_id", "test-trace-123")
	newLogger := logger.WithTraceID(ctx)

	assert.NotNil(t, newLogger)
	assert.NotPanics(t, func() {
		newLogger.Info("test with trace id")
	})
}

func TestLogger_WithTraceID_WithoutTraceIDInContext(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	ctx := context.Background()
	newLogger := logger.WithTraceID(ctx)

	assert.NotNil(t, newLogger)
	// Should return the same logger when no trace ID in context
	assert.Equal(t, logger, newLogger)
}

func TestLogger_convertFields_StringValue(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	assert.NotPanics(t, func() {
		logger.Info("test", "string_key", "string_value")
	})
}

func TestLogger_convertFields_IntValue(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	assert.NotPanics(t, func() {
		logger.Info("test", "int_key", 42)
	})
}

func TestLogger_convertFields_Int64Value(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	assert.NotPanics(t, func() {
		logger.Info("test", "int64_key", int64(123456789))
	})
}

func TestLogger_convertFields_ErrorValue(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	testErr := assert.AnError

	assert.NotPanics(t, func() {
		logger.Info("test", "error", testErr)
	})
}

func TestLogger_convertFields_AnyValue(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	type customStruct struct {
		Field string
	}

	assert.NotPanics(t, func() {
		logger.Info("test", "custom_key", customStruct{Field: "value"})
	})
}

func TestLogger_convertFields_MultipleFields(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	assert.NotPanics(t, func() {
		logger.Info("test",
			"string_key", "string_value",
			"int_key", 42,
			"int64_key", int64(123),
		)
	})
}

func TestLogger_convertFields_OddNumberOfFields(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)

	// Should handle odd number of fields gracefully (last key without value is ignored)
	assert.NotPanics(t, func() {
		logger.Info("test", "key1", "value1", "key2")
	})
}
