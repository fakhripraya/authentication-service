package data

import (
	"github.com/fakhripraya/authentication-service/migrate"

	"github.com/hashicorp/go-hclog"
	"github.com/jinzhu/gorm"
)

// MigrateDB is a function that migrate the defined list of table
func MigrateDB(db *gorm.DB) {
	hclog.Default().Info("Migrating tables into the database")
	db.Set("gorm:table_options", "ENGINE=InnoDB").AutoMigrate(
		&migrate.MasterUser{},
		&migrate.MasterUserLogin{},
		&migrate.MasterAccess{},
		&migrate.MasterRole{})
	return
}
