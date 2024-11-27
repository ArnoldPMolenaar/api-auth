package cache

import (
	"github.com/ArnoldPMolenaar/api-utils/utils"
	"github.com/valkey-io/valkey-go"
	"os"
	"strconv"
)

// ValkeyConnection func for connect to Valkey server.
func ValkeyConnection() (valkey.Client, error) {
	// Define Valkey database number.
	dbNumber, _ := strconv.Atoi(os.Getenv("REDIS_DB_NUMBER"))

	// Build Valkey URL.
	valkeyURL, err := utils.ConnectionURLBuilder("redis")
	if err != nil {
		return nil, err
	}

	// Set Valkey options.
	options := valkey.ClientOption{
		InitAddress:       []string{valkeyURL},
		ForceSingleClient: true,
		SelectDB:          dbNumber,
		ClientName:        os.Getenv("VALKEY_CLIENT_NAME"),
		Username:          os.Getenv("VALKEY_USERNAME"),
		Password:          os.Getenv("VALKEY_PASSWORD"),
	}

	client, err := valkey.NewClient(options)
	if err != nil {
		panic(err)
	}

	return client, nil
}
