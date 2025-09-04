package logger

import "testing"

func TestLoggerFunctions(t *testing.T) {
	Init("invalid") // should default to info
	if log == nil {
		t.Fatal("log not initialized")
	}
	// Avoid os.Exit on Fatal
	log.ExitFunc = func(int) {}

	Debug("debug")
	Info("info")
	Warn("warn")
	Error("error")
	Debugf("%s", "debugf")
	Infof("%s", "infof")
	Warnf("%s", "warnf")
	Errorf("%s", "errorf")
	Fatal("fatal")
	Fatalf("%s", "fatalf")
}
