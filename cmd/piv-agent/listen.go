package main

import (
	"fmt"

	"go.uber.org/zap"
)

// ListenCmd represents the listen command.
type ListenCmd struct {
}

// Run the listen command to start listening for ssh-agent requests.
func (cmd *ListenCmd) Run() error {
	log, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("couldn't init logger: %w", err)
	}
	defer log.Sync()
	log.Info("startup", zap.String("version", version), zap.String("buildTime", buildTime))
	return nil
}
