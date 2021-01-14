package database

import "time"

// MasterUser is an entity that directly communicate with the MasterUser table in the database
type MasterUser struct {
	ID             uint      `gorm:"primaryKey;not null;autoIncrement" json:"id"`
	RoleID         uint      `gorm:"not null" json:"role_id"`
	Username       string    `gorm:"unique;not null" json:"username"`
	DisplayName    string    `gorm:"not null" json:"displayname"`
	Password       []byte    `gorm:"not null" json:"password"`
	Email          string    `json:"email"`
	Phone          string    `json:"phone"`
	LoginFailCount uint      `gorm:"default:0"`
	IsVerified     bool      `gorm:"default:false" json:"is_verified"`
	IsActive       bool      `gorm:"default:true" json:"is_active"`
	Created        time.Time `gorm:"type:datetime" json:"created"`
	CreatedBy      string    `json:"created_by"`
	Modified       time.Time `gorm:"type:datetime" json:"modified"`
	ModifiedBy     string    `json:"modified_by"`
}

// MasterUserTable set the migrated struct table name
func (masterUser *MasterUser) MasterUserTable() string {
	return "dbMasterUser"
}
