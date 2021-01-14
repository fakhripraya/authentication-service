package database

import "time"

// MasterRoleAccess is an entity that directly communicate with the MasterRoleAccess table in the database
type MasterRoleAccess struct {
	AccessID   uint      `gorm:"primary_key;not null" json:"id"`
	RoleID     uint      `gorm:"primary_key;not null" json:"role_id"`
	Created    time.Time `gorm:"type:datetime" json:"created"`
	CreatedBy  string    `json:"created_by"`
	Modified   time.Time `gorm:"type:datetime" json:"modified"`
	ModifiedBy string    `json:"modified_by"`
}

// MasterRoleAccessTable set the migrated struct table name
func (masterRoleAccess *MasterRoleAccess) MasterRoleAccessTable() string {
	return "dbMasterAccess"
}
