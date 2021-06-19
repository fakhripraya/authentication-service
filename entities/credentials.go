package entities

import "time"

// CredentialsDB used to define credentials from the client side
type CredentialsDB struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"` /// TODO: will edit the password validation here
	OTPCode  string `json:"otp_code,omitempty"` /// TODO: will edit the otp code validation here
}

// O2AuthCredentialsDB used to define O2Auth credentials from the client side
type O2AuthCredentialsDB struct {
	RedirectURL string `json:"redirectUri"`
}

// UserInfo used is a struct for current logged in user info
type UserInfo struct {
	ID             uint      `gorm:"primaryKey;not null;autoIncrement" json:"id"`
	RoleID         uint      `gorm:"not null" json:"role_id"`
	Username       string    `gorm:"unique;not null" json:"username"`
	DisplayName    string    `gorm:"not null" json:"displayname"`
	Email          string    `json:"email"`
	Phone          string    `json:"phone"`
	ProfilePicture string    `json:"profile_picture"`
	City           string    `gorm:"not null" json:"city"`
	LoginFailCount uint      `gorm:"default:0"`
	IsVerified     bool      `gorm:"not null;default:false" json:"is_verified"`
	IsActive       bool      `gorm:"not null;default:true" json:"is_active"`
	Created        time.Time `gorm:"type:datetime" json:"created"`
	CreatedBy      string    `json:"created_by"`
	Modified       time.Time `gorm:"type:datetime" json:"modified"`
	ModifiedBy     string    `json:"modified_by"`
}
