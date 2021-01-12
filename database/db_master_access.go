package database

import "time"

// MasterAccess is an entity that directly communicate with the MasterAccess table in the database
type MasterAccess struct {
	ID         uint      `gorm:"primary_key;autoIncrement;not null" json:"id"`
	RoleID     uint      `gorm:"not null" json:"role_id"`
	Name       string    `gorm:"not null" json:"access_name"`
	IsActive   bool      `gorm:"default:true" json:"is_active"`
	Created    time.Time `gorm:"type:datetime" json:"created"`
	CreatedBy  string    `json:"created_by"`
	Modified   time.Time `gorm:"type:datetime" json:"modified"`
	ModifiedBy string    `json:"modified_by"`
}

// MasterAccessTable set the migrated struct table name
func (masterAccess *MasterAccess) MasterAccessTable() string {
	return "dbMasterAccess"
}
