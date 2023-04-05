package log

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func Init() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
}

func Info(s string) {
	gologger.Info().Msgf(s)
}

func Infof(s string, v ...interface{}) {
	gologger.Info().Msgf(s, v...)
}

func Debug(s string) {
	gologger.Debug().Msgf(s)
}

func Debugf(s string, v ...interface{}) {
	gologger.Debug().Msgf(s, v...)
}

func Warning(s string) {
	gologger.Warning().Msgf(s)
}

func Warningf(s string, v ...interface{}) {
	gologger.Warning().Msgf(s, v...)
}

func Error(s string) {
	gologger.Error().Msgf(s)
}

func Errorf(s string, v ...interface{}) {
	gologger.Error().Msgf(s, v...)
}

func Fatal(s string) {
	gologger.Fatal().Msgf(s)
}

func Fatalf(s string, v ...interface{}) {
	gologger.Fatal().Msgf(s, v...)
}

func Print(s string) {
	gologger.Print().Msgf(s)
}

func Printf(s string, v ...interface{}) {
	gologger.Print().Msgf(s, v...)
}
