package service

import "regexp"

// IsEmail checks if a string is a valid email address
func IsEmail(s string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(s)
}

// IsPhone checks if a string is a valid phone number
func IsPhone(s string) bool {
	phoneRegex := regexp.MustCompile(`^\+?[0-9]{10,15}$`)
	return phoneRegex.MatchString(s)
}
