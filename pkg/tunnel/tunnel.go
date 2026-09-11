package tunnel

import (
	"stormdns-go/internal/client"
	"stormdns-go/internal/config"
	"stormdns-go/internal/logger"
)

type (
	Client          = client.Client
	ClientConfig    = config.ClientConfig
	ResolverAddress = config.ResolverAddress
	Logger          = logger.Logger
)

func DiscardLogger() {
	logger.DiscardLogs()
}

func DefaultClientConfig() ClientConfig {
	return config.DefaultClientConfig()
}

func Bootstrap(cfg ClientConfig, path string) (*Client, error) {
	return client.BootstrapLoadedConfig(cfg, path)
}
