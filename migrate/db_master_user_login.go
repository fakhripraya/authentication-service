package migrate

import "time"

// MasterUserLogin will migrate a master user login table with the given specification into the database
type MasterUserLogin struct {
	ID            uint      `gorm:"primaryKey;not null;autoIncrement" json:"id"`
	UserID        uint      `gorm:"not null" json:"user_id"`
	LoginProvider string    `gorm:"not null" json:"login_provider"`
	ProviderKey   string    `gorm:"not null" json:"provider_key"`
	Created       time.Time `gorm:"type:datetime" json:"created"`
	CreatedBy     string    `json:"created_by"`
	Modified      time.Time `gorm:"type:datetime" json:"modified"`
	ModifiedBy    string    `json:"modified_by"`
}

// TableName set the migrated struct table name
func (user *MasterUserLogin) TableName() string {
	return "dbMasterUserLogin"
}
