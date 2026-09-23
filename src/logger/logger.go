package logger

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

var log *slog.Logger

func Init(level string) {
	var min slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		min = slog.LevelDebug
	case "warn", "warning":
		min = slog.LevelWarn
	case "error":
		min = slog.LevelError
	default:
		min = slog.LevelInfo
	}
	log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: min}))
	if level != "" && level != "info" && min == slog.LevelInfo {
		log.Warn("invalid log level; using info", "level", level)
	}
}

func Debug(args ...interface{})                 { log.Debug(fmt.Sprint(args...)) }
func Info(args ...interface{})                  { log.Info(fmt.Sprint(args...)) }
func Warn(args ...interface{})                  { log.Warn(fmt.Sprint(args...)) }
func Error(args ...interface{})                 { log.Error(fmt.Sprint(args...)) }
func Debugf(format string, args ...interface{}) { log.Debug(fmt.Sprintf(format, args...)) }
func Infof(format string, args ...interface{})  { log.Info(fmt.Sprintf(format, args...)) }
func Warnf(format string, args ...interface{})  { log.Warn(fmt.Sprintf(format, args...)) }
func Errorf(format string, args ...interface{}) { log.Error(fmt.Sprintf(format, args...)) }
