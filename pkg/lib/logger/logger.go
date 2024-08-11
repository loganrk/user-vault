package logger

import (
	"context"

	"mayilon/pkg/lib/logger/zapLogger"
)

const (
	ENCODING_TYPE_JSON    = 1
	ENCODING_TYPE_CONSOLE = 2
)

type Config struct {
	Level           int
	Encoding        int
	EncodingCaller  bool
	OutputPath      string
	ErrorOutputPath string
}

type Logger interface {
	Debug(ctx context.Context, messages ...any)
	Info(ctx context.Context, messages ...any)
	Warn(ctx context.Context, messages ...any)
	Error(ctx context.Context, messages ...any)
	Fatal(ctx context.Context, messages ...any)
	Debugf(ctx context.Context, template string, args ...any)
	Infof(ctx context.Context, template string, args ...any)
	Warnf(ctx context.Context, template string, args ...any)
	Errorf(ctx context.Context, template string, args ...any)
	Fatalf(ctx context.Context, template string, args ...any)
	Debugw(ctx context.Context, msg string, keysAndValues ...any)
	Infow(ctx context.Context, msg string, keysAndValues ...any)
	Warnw(ctx context.Context, msg string, keysAndValues ...any)
	Errorw(ctx context.Context, msg string, keysAndValues ...any)
	Fatalw(ctx context.Context, msg string, keysAndValues ...any)
	Sync(ctx context.Context) error
}

func New(config Config) (Logger, error) {
	var encodingType string
	if config.Encoding == ENCODING_TYPE_CONSOLE {
		encodingType = "console"
	} else if config.Encoding == ENCODING_TYPE_JSON {
		encodingType = "json"
	}

	return zapLogger.New(config.Level, encodingType, config.EncodingCaller, config.OutputPath, config.ErrorOutputPath)
}
