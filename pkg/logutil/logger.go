package logutil

import "go.uber.org/zap"

var logger *zap.Logger

func InitLogger() {
  var err error
	// Use Production or Development logger depending on your needs
	logger, err = zap.NewProduction()
	if err != nil {
		panic(err)
	}
}

func GetLogger() *zap.Logger{
  return logger
}
