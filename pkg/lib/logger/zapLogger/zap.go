package zapLogger

import (
	"context"
	"fmt"
	"runtime"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type zapLog struct {
	logger *zap.Logger
	sugar  *zap.SugaredLogger
}

func New(level int, encoding string, encodingCaller bool, outputPath, errorOutputPath string) (*zapLog, error) {
	zapLevel, err := intToZapLevel(level)
	if err != nil {
		return nil, err
	}

	zapConfig := zap.Config{
		Level:       zap.NewAtomicLevelAt(zapLevel),
		Development: false,
		Encoding:    encoding,
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "time",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.CapitalLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{outputPath},
		ErrorOutputPaths: []string{errorOutputPath},
	}

	if encodingCaller {
		zapConfig.EncoderConfig.EncodeCaller = callerEncoder
	}

	logger, err := zapConfig.Build()
	if err != nil {
		return nil, err
	}

	return &zapLog{
		logger: logger,
		sugar:  logger.Sugar(),
	}, nil
}

func (l *zapLog) Debug(ctx context.Context, messages ...any) {
	l.sugar.Debug(messages...)
}

func (l *zapLog) Info(ctx context.Context, messages ...any) {
	l.sugar.Info(messages...)
}

func (l *zapLog) Warn(ctx context.Context, messages ...any) {
	l.sugar.Warn(messages...)
}

func (l *zapLog) Error(ctx context.Context, messages ...any) {
	l.sugar.Error(messages...)
}

func (l *zapLog) Fatal(ctx context.Context, messages ...any) {
	l.sugar.Fatal(messages...)
}

func (l *zapLog) Debugf(ctx context.Context, template string, args ...any) {
	l.sugar.Debugf(template, args...)
}

func (l *zapLog) Infof(ctx context.Context, template string, args ...any) {
	l.sugar.Infof(template, args...)
}

func (l *zapLog) Warnf(ctx context.Context, template string, args ...any) {
	l.sugar.Warnf(template, args...)
}

func (l *zapLog) Errorf(ctx context.Context, template string, args ...any) {
	l.sugar.Errorf(template, args...)
}

func (l *zapLog) Fatalf(ctx context.Context, template string, args ...any) {
	l.sugar.Fatalf(template, args...)
}

func (l *zapLog) Debugw(ctx context.Context, msg string, keysAndValues ...any) {
	l.sugar.Debugw(msg, keysAndValues...)
}

func (l *zapLog) Infow(ctx context.Context, msg string, keysAndValues ...any) {
	l.sugar.Infow(msg, keysAndValues...)
}

func (l *zapLog) Warnw(ctx context.Context, msg string, keysAndValues ...any) {
	l.sugar.Warnw(msg, keysAndValues...)
}

func (l *zapLog) Errorw(ctx context.Context, msg string, keysAndValues ...any) {
	l.sugar.Errorw(msg, keysAndValues...)
}

func (l *zapLog) Fatalw(ctx context.Context, msg string, keysAndValues ...any) {
	l.sugar.Fatalw(msg, keysAndValues...)
}

func (l *zapLog) Sync(ctx context.Context) error {
	return l.logger.Sync()
}

func intToZapLevel(level int) (zapcore.Level, error) {
	switch level {
	case 0:
		return zapcore.DebugLevel, nil
	case 1:
		return zapcore.InfoLevel, nil
	case 2:
		return zapcore.WarnLevel, nil
	case 3:
		return zapcore.ErrorLevel, nil
	case 4:
		return zapcore.DPanicLevel, nil
	case 5:
		return zapcore.PanicLevel, nil
	case 6:
		return zapcore.FatalLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("invalid log level: %d", level)
	}
}

// Custom caller encoder to include function name
func callerEncoder(caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
	functionName := getFunctionName(2) // Get the calling function's name
	enc.AppendString(fmt.Sprintf("%s:%d %s", caller.TrimmedPath(), caller.Line, functionName))
}

// Helper function to retrieve the function name
func getFunctionName(skip int) string {
	pc, _, _, ok := runtime.Caller(skip)
	if !ok {
		return "unknown"
	}
	function := runtime.FuncForPC(pc)
	if function == nil {
		return "unknown"
	}
	return function.Name()
}
