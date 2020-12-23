package entities

// CredentialsDB used to define credentials from the database
type CredentialsDB struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"` /// TODO: will edit the password validation here
	OTPCode  string `json:"otp_code,omitempty"` /// TODO: will edit the otp code validation here
}
