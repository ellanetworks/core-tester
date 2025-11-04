// Copyright 2024 Ella Networks

package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	log               *zap.Logger
	EllaCoreTesterLog *zap.SugaredLogger
	GnbLog            *zap.SugaredLogger
	UELog             *zap.SugaredLogger
	atomicLevel       zap.AtomicLevel
)

// init sets up a default logger that writes to stdout.
// This configuration is used in tests and whenever ConfigureLogging is not called.
func init() {
	atomicLevel = zap.NewAtomicLevelAt(zap.InfoLevel)

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.LevelKey = "level"
	encoderConfig.EncodeLevel = CapitalColorLevelEncoder
	encoderConfig.CallerKey = "caller"
	encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	encoderConfig.MessageKey = "message"
	encoderConfig.StacktraceKey = ""

	config := zap.Config{
		Level:            atomicLevel,
		Development:      false,
		Encoding:         "console",
		DisableCaller:    false,
		EncoderConfig:    encoderConfig,
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	var err error

	log, err = config.Build()
	if err != nil {
		panic(err)
	}

	// System logs for various components
	GnbLog = log.Sugar().With("component", "Gnb")
	UELog = log.Sugar().With("component", "UE")
	EllaCoreTesterLog = log.Sugar().With("component", "EllaCoreTester")
}

func ConfigureLogging(level string) error {
	zapLevel, err := zapcore.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("failed to parse log level: %v", err)
	}

	atomicLevel.SetLevel(zapLevel)

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.LevelKey = "level"
	encoderConfig.EncodeLevel = CapitalColorLevelEncoder
	encoderConfig.CallerKey = "caller"
	encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	encoderConfig.MessageKey = "message"
	encoderConfig.StacktraceKey = ""

	sysConfig := zap.Config{
		Level:            atomicLevel,
		Development:      false,
		Encoding:         "console",
		DisableCaller:    false,
		EncoderConfig:    encoderConfig,
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	newSysLogger, err := sysConfig.Build()
	if err != nil {
		return fmt.Errorf("failed to build system logger: %w", err)
	}

	log = newSysLogger
	GnbLog = log.Sugar().With("component", "Gnb")
	UELog = log.Sugar().With("component", "UE")
	EllaCoreTesterLog = log.Sugar().With("component", "EllaCoreTester")

	return nil
}

func CapitalColorLevelEncoder(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	var color string

	switch l {
	case zapcore.DebugLevel:
		color = "\033[37m" // White
	case zapcore.InfoLevel:
		color = "\033[32m" // Green
	case zapcore.WarnLevel:
		color = "\033[33m" // Yellow
	case zapcore.ErrorLevel:
		color = "\033[31m" // Red
	case zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		color = "\033[35m" // Magenta
	default:
		color = "\033[0m" // Reset
	}

	enc.AppendString(fmt.Sprintf("%s%s\033[0m", color, l.CapitalString()))
}
