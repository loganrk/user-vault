package config

type Logger interface {
	GetLoggerLevel() string
	GetLoggerEncodingMethod() string
	GetLoggerEncodingCaller() bool
	GetLoggerPath() string
	GetLoggerErrorPath() string
}

func (l logger) GetLoggerLevel() string {
	return l.Level

}

func (l logger) GetLoggerEncodingMethod() string {
	return l.Encoding.Method

}

func (l logger) GetLoggerEncodingCaller() bool {
	return l.Encoding.Caller

}

func (l logger) GetLoggerPath() string {
	return l.Path

}

func (l logger) GetLoggerErrorPath() string {
	return l.ErrPath

}
