package data

import (
	"github.com/fakhripraya/authentication-service/entities"

	"os"
	"strings"

	"github.com/spf13/viper"
)

// MySigningKey is a variable that defines JWT secret
var MySigningKey string

// ConfigInit is a function to initialize app configuration
func ConfigInit(config *entities.Configuration) error {
	// determine the application state via env
	var environment string
	if os.Getenv("APP_STATE") != "production" && os.Getenv("APP_STATE") != "prod" {
		environment = "development"
	} else {
		environment = "production"
	}

	viper.SetConfigName("config." + environment)
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()

	// Change _ underscore in env to . dot notation in viper
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	// Read config
	if err := viper.ReadInConfig(); err != nil {
		return err
	}

	err := viper.Unmarshal(&config)
	if err != nil {
		return err
	}

	MySigningKey = config.Jwt.Secret

	return nil
}
