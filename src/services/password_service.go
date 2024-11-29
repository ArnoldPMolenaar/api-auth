package services

import (
	gopassword "github.com/sethvargo/go-password/password"
	"golang.org/x/crypto/bcrypt"
)

// PasswordHash generates a bcrypt hash from the given password.
func PasswordHash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// PasswordCompare validates the given password with the stored hashed password.
func PasswordCompare(enteredPassword, storedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(enteredPassword))

	return err == nil
}

// PasswordGenerate generates a random password with a given length, amount of numbers and amount of symbols.
func PasswordGenerate(length, numDigits, numSymbols int) (string, error) {
	pass, err := gopassword.Generate(length, numDigits, numSymbols, false, false)
	if err != nil {
		return "", err
	}

	return pass, nil
}
