package utils

import "regexp"

const (
	phoneNumberPattern = `^\+62[0-9]+$`
	upperCharPattern   = `.*[A-Z].*`
	digitCharPattern   = `.*[0-9].*`
	specialCharPattern = `.*\W.*`
)

var (
	phoneNumberRegex = regexp.MustCompile(phoneNumberPattern)
	upperCharRegex   = regexp.MustCompile(upperCharPattern)
	digitCharRegex   = regexp.MustCompile(digitCharPattern)
	specialCharRegex = regexp.MustCompile(specialCharPattern)
)

func IsValidPassword(password string) bool {
	return upperCharRegex.MatchString(password) &&
		digitCharRegex.MatchString(password) &&
		specialCharRegex.MatchString(password)
}

func IsValidPhoneNumber(phoneNumber string) bool {
	return phoneNumberRegex.MatchString(phoneNumber)
}
