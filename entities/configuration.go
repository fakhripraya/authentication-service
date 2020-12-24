package entities

// Configuration Entity
type Configuration struct {
	API        APIConfiguration
	Database   DatabaseConfiguration
	Jwt        JwtConfiguration
	MySQLStore MySQLStoreConfiguration
}

// APIConfiguration is an entity that stores the app configuration
type APIConfiguration struct {
	Environment string
	Host        string
	Port        int
	Debug       bool
}

// DatabaseConfiguration is an entity that stores the database configuration
type DatabaseConfiguration struct {
	Host     string
	Port     int
	User     string
	Password string
	Dbname   string
}

// JwtConfiguration is an entity that stores the JWT secret
type JwtConfiguration struct {
	Secret string
}

// MySQLStoreConfiguration is an entity that stores the MySqlStore secret
type MySQLStoreConfiguration struct {
	Secret string
}
