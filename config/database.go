package config

import (
	"fmt"

	"github.com/fakhripraya/authentication-service/entities"

	"github.com/jinzhu/gorm"
)

// DB is an ORM for MYSQL database
var DB *gorm.DB

// DBConfig represents db configuration
type DBConfig struct {
	Host     string
	Port     int
	User     string
	DBName   string
	Password string
}

// BuildDBConfig is a function that builds the database config based on DBConfig structure
func BuildDBConfig(db *entities.DatabaseConfiguration) *DBConfig {
	dbConfig := DBConfig{
		Host:     db.Host,
		Port:     db.Port,
		User:     db.User,
		Password: db.Password,
		DBName:   db.Dbname,
	}
	return &dbConfig
}

// DbURL is a function that returns the connected db url
func DbURL(dbConfig *DBConfig) string {
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8&parseTime=True&loc=Local",
		dbConfig.User,
		dbConfig.Password,
		dbConfig.Host,
		dbConfig.Port,
		dbConfig.DBName,
	)
}
