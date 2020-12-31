package mailer

import (
	"bytes"
	"html/template"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/hashicorp/go-hclog"
)

// emailRegex is a regular expression to match standard email structure
var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

// waRegex is a regular expression to match standard phone structure
var waRegex = regexp.MustCompile(`\+?([ -]?\d+)+|\(\d+\)([ -]\d+)`)

// Email is a struct for email variable
type Email struct {
	logger hclog.Logger
}

// NewEmail creates a new email handler
func NewEmail(logger hclog.Logger) *Email {
	return &Email{
		logger: logger,
	}
}

// ParseTemplate is a function to parse an email template to Email body
func (email *Email) ParseTemplate(templateFileName string, data interface{}) (string, error) {

	// Get the application working directory
	workingDirectiory, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	tmp, err := template.ParseFiles(workingDirectiory + templateFileName)
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	if err = tmp.Execute(buf, data); err != nil {
		return "", err
	}
	emailTemplate := buf.String()
	return emailTemplate, nil
}

// IsEmailValid checks if the email provided passes the required structure
// and length test. It also checks the domain has a valid MX record.
func IsEmailValid(email string) bool {

	// length test
	if len(email) < 3 && len(email) > 254 {
		return false
	}

	// regex test
	if !emailRegex.MatchString(email) {
		return false
	}

	// MX record test
	parts := strings.Split(email, "@")
	mx, err := net.LookupMX(parts[1])
	if err != nil || len(mx) == 0 {
		return false
	}

	return true
}

// IsWhatsAppValid checks if the WA provided passes the required structure
// and length test.
func IsWhatsAppValid(waNumber string) bool {
	// length test
	if len(waNumber) < 8 {
		return false
	}

	// regex test
	if !waRegex.MatchString(waNumber) {
		return false
	}

	return true
}
