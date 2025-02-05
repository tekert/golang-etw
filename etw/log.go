//go:build windows

package etw

import (
	"os"

	plog "github.com/phuslu/log"
)

// Etw package-wide default logger
var log = plog.Logger{
	Writer: plog.WriterFunc(func(e *plog.Entry) (int, error) {
		if e.Level >= plog.ErrorLevel {
			return os.Stderr.Write(e.Value())
		} else {
			return os.Stdout.Write(e.Value())
		}
	}),
	Level: plog.InfoLevel, // Default
}

// SetLogger replaces the package-wide default logger
//
// http://github.com/phuslu/log is used for logging
func SetLogger(newLogger *plog.Logger) {
	if newLogger != nil {
		log = *newLogger
	}
}

// SetLoggerLevel sets the log level (e.g., log.InfoLevel, log.DebugLevel)
func SetLoggerLevel(lvl plog.Level) {
	log.SetLevel(lvl)
}

// SetDebugLevel sets the log level to log.DebugLevel
func SetDebugLevel() {
	log.SetLevel(plog.DebugLevel)
}

// SetTraceLevel sets the log level to log.TraceLevel
func SetTraceLevel() {
	log.SetLevel(plog.TraceLevel)
}

// SetInfoLevel sets the log level to log.InfoLevel
func SetInfoLevel() {
	log.SetLevel(plog.InfoLevel)
}

// SetWarnLevel sets the log level to log.WarnLevel
func SetWarnLevel() {
	log.SetLevel(plog.WarnLevel)
}

// SetErrorLevel sets the log level to log.ErrorLevel
func SetErrorLevel() {
	log.SetLevel(plog.ErrorLevel)
}

// SetFatalLevel sets the log level to log.FatalLevel
func SetFatalLevel() {
	log.SetLevel(plog.FatalLevel)
}

// SetPanicLevel sets the log level to log.PanicLevel
func SetPanicLevel() {
	log.SetLevel(plog.PanicLevel)
}

// DisableLogging disables all logging output
func DisableLogging() {
	log.SetLevel(plog.Level(99)) // Above noLevel
}

// TODO(tekert): file logging, etc
