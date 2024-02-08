package utils

import "golang.org/x/crypto/bcrypt"

func GenerateHash(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", nil
	}

	return string(hashedPassword), nil
}
