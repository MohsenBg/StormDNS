package client

import (
	"fmt"

	"stormdns-go/internal/config"
	"stormdns-go/internal/logger"
	"stormdns-go/internal/security"
)

// BootstrapLoadedConfig initializes a new Client from an in-memory config,
// without requiring a TOML file on disk. It mirrors Bootstrap but skips
// config file loading so embedders (e.g. bgscan) can construct the config
// programmatically and pass resolvers directly.
func BootstrapLoadedConfig(cfg config.ClientConfig, logPath string) (*Client, error) {
	cfg.ApplyStartupModeMTU("resolvers")

	var log *logger.Logger
	if logPath != "" {
		log = logger.NewWithFile("StormDNS Client", cfg.LogLevel, logPath)
	} else {
		log = logger.New("StormDNS Client", cfg.LogLevel)
	}

	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("client codec setup failed: %w", err)
	}

	c := New(cfg, log, codec)
	if err := c.BuildConnectionMap(); err != nil {
		if c.log != nil {
			c.log.Errorf("<red>%v</red>", err)
		}
		return nil, err
	}

	if cacheLogPath := cfg.ResolvedResolverCacheLogPath(); cacheLogPath != "" {
		c.openResolverCacheLog(cacheLogPath)
	}

	return c, nil
}
