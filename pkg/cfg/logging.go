package cfg

import (
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"gopkg.in/natefinch/lumberjack.v2"
)

type LoggingConfig struct {
	LogLevel     *log.Level `yaml:"log_level"`
	LogMedia     string     `yaml:"log_media"`
	LogDir       string     `yaml:"log_dir"`
	LogMaxSize   int        `yaml:"log_max_size"`
	LogMaxAge    int        `yaml:"log_max_age"`
	LogMaxFiles  int        `yaml:"log_max_backups"`
	CompressLogs *bool      `yaml:"compress_logs"`
}

func (c *LoggingConfig) LoggerForFile(fileName string) (io.Writer, error) {
	if c.LogMedia == "stdout" {
		return os.Stderr, nil
	}

	logPath, err := setLogFilePermissions(c.LogDir, fileName)
	if err != nil {
		return nil, err
	}

	l := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    c.LogMaxSize,
		MaxBackups: c.LogMaxFiles,
		MaxAge:     c.LogMaxAge,
		Compress:   *c.CompressLogs,
	}

	return l, nil
}

func (c *LoggingConfig) setDefaults() {
	if c.LogMedia == "" {
		c.LogMedia = "stdout"
	}

	if c.LogDir == "" {
		c.LogDir = "/var/log/"
	}

	if c.LogLevel == nil {
		defaultLevel := log.InfoLevel
		c.LogLevel = &defaultLevel
	}

	if c.LogMaxSize == 0 {
		c.LogMaxSize = 40
	}

	if c.LogMaxFiles == 0 {
		c.LogMaxFiles = 3
	}

	if c.LogMaxAge == 0 {
		c.LogMaxAge = 30
	}

	if c.CompressLogs == nil {
		defaultCompress := true
		c.CompressLogs = &defaultCompress
	}
}

func (c *LoggingConfig) validate() error {
	if c.LogMedia != "stdout" && c.LogMedia != "file" {
		return fmt.Errorf("log_media should be either 'stdout' or 'file'")
	}
	return nil
}

func (c *LoggingConfig) setup(fileName string) error {
	c.setDefaults()
	if err := c.validate(); err != nil {
		return err
	}
	log.SetLevel(*c.LogLevel)

	if c.LogMedia == "stdout" {
		return nil
	}

	log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})

	logger, err := c.LoggerForFile(fileName)
	if err != nil {
		return err
	}

	log.SetOutput(logger)

	// keep stderr for panic/fatal, otherwise process failures
	// won't be visible enough
	log.AddHook(&writer.Hook{
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
		},
	})

	return nil
}
