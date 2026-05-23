package cache

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ArnoldPMolenaar/api-utils/cache"
	"github.com/valkey-io/valkey-go"
)

var Valkey valkey.Client

// OpenValkeyConnection Start a new valkey connection.
func OpenValkeyConnection() error {
	// Open connection to valkey.
	client, err := cache.ValkeyConnection()
	if err != nil {
		return err
	}

	// Set the global Valkey variable.
	Valkey = client

	return nil
}

// ReadinessCheck verifies that the cache connection is initialized and reachable.
func ReadinessCheck() error {
	if Valkey == nil {
		return errors.New("cache connection is not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result := Valkey.Do(ctx, Valkey.B().Arbitrary("PING").Build())
	if result.Error() != nil {
		return fmt.Errorf("cache ping failed: %w", result.Error())
	}

	pong, err := result.ToString()
	if err != nil {
		return fmt.Errorf("cache ping response invalid: %w", err)
	}
	if !strings.EqualFold(pong, "PONG") {
		return fmt.Errorf("cache ping response unexpected: %s", pong)
	}

	return nil
}

