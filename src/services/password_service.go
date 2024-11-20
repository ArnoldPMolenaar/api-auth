package services

import (
	customerr "api-auth/main/src/errors"
	"errors"
	"github.com/sethvargo/go-password/password"
	"golang.org/x/crypto/bcrypt"
)

// PasswordHash generates a bcrypt hash from the given password.
func PasswordHash(password string) (string, error) {
	if password == "" {
		return "", errors.New(customerr.PasswordEmpty)
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// PasswordHashValidate validates the given password with the stored hashed password.
func PasswordHashValidate(enteredPassword string, storedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(enteredPassword))

	return err == nil
}

// PasswordGenerate generates a random password with a given length, amount of numbers and amount of symbols.
func PasswordGenerate(length int, numDigits int, numSymbols int) (string, error) {
	pass, err := password.Generate(length, numDigits, numSymbols, false, false)
	if err != nil {
		return "", err
	}

	return pass, nil
}
