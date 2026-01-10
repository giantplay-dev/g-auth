package logger

import (
	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	*zap.Logger
}

func NewLogger(env string) (*Logger, error) {
	var zapLogger *zap.Logger
	var err error

	if env == "production" {
		// production config: JSON format, no caller
		config := zap.NewProductionConfig()
		config.DisableCaller = true
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		zapLogger, err = config.Build()
	} else {
		// development config: JSON format, no caller, colorized console
		config := zap.NewDevelopmentConfig()
		config.DisableCaller = true
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.Encoding = "console" // Use console encoding for better readability in dev
		zapLogger, err = config.Build()
	}

	if err != nil {
		return nil, err
	}

	return &Logger{zapLogger}, nil
}

func (l *Logger) Info(msg string, fields ...interface{}) {
	l.Logger.Info(msg, l.convertFields(fields...)...)
}

func (l *Logger) Error(msg string, fields ...interface{}) {
	l.Logger.Error(msg, l.convertFields(fields...)...)
}

func (l *Logger) Warn(msg string, fields ...interface{}) {
	l.Logger.Warn(msg, l.convertFields(fields...)...)
}

func (l *Logger) Debug(msg string, fields ...interface{}) {
	l.Logger.Debug(msg, l.convertFields(fields...)...)
}

func (l *Logger) Fatal(msg string, fields ...interface{}) {
	l.Logger.Fatal(msg, l.convertFields(fields...)...)
}

func (l *Logger) With(fields ...interface{}) *Logger {
	return &Logger{l.Logger.With(l.convertFields(fields...)...)}
}

func (l *Logger) WithTraceID(ctx context.Context) *Logger {
	if traceID := ctx.Value("trace_id"); traceID != nil {
		return &Logger{l.Logger.With(zap.String("trace_id", traceID.(string)))}
	}
	return l
}

func (l *Logger) convertFields(fields ...interface{}) []zap.Field {
	zapFields := make([]zap.Field, 0, len(fields)/2)
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			key := fields[i].(string)
			value := fields[i+1]

			switch v := value.(type) {
			case string:
				zapFields = append(zapFields, zap.String(key, v))
			case int:
				zapFields = append(zapFields, zap.Int(key, v))
			case int64:
				zapFields = append(zapFields, zap.Int64(key, v))
			case error:
				zapFields = append(zapFields, zap.Error(v))
			default:
				zapFields = append(zapFields, zap.Any(key, v))
			}
		}
	}
	return zapFields
}
