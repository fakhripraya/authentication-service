package mailer

import (
	"bytes"
	"html/template"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/fakhripraya/authentication-service/entities"

	"github.com/hashicorp/go-hclog"
	"gopkg.in/gomail.v2"
)

var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

// Email is a struct for email variable
type Email struct {
	cred   *entities.EmailCredential
	logger hclog.Logger
}

// NewEmail creates a new email handler
func NewEmail(cred *entities.EmailCredential, logger hclog.Logger) *Email {
	return &Email{
		cred:   cred,
		logger: logger,
	}
}

// SendEmail is a function to send email via gomail
func (email *Email) SendEmail(to, cc []string, subject, body string) error {

	// creating new gomail message
	mail := gomail.NewMessage()
	mail.SetHeader("From", email.cred.Username)
	mail.SetHeader("To", to...)
	mail.SetHeader("Cc", cc...)
	mail.SetHeader("Subject", subject)
	mail.SetBody("text/html", body)

	dialer := gomail.NewDialer("smtp.gmail.com", 587, email.cred.Username, email.cred.Password)

	// Send the email
	if err := dialer.DialAndSend(mail); err != nil {
		return err
	}

	return nil
}

// ParseTemplate is a function to parse an email template to Email body
func (email *Email) ParseTemplate(templateFileName string, data interface{}) (string, error) {
	email.logger.Info("Parsing Email")

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
	if len(email) < 3 && len(email) > 254 {
		return false
	}
	if !emailRegex.MatchString(email) {
		return false
	}
	parts := strings.Split(email, "@")
	mx, err := net.LookupMX(parts[1])
	if err != nil || len(mx) == 0 {
		return false
	}
	return true
}
