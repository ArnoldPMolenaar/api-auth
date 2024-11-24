package enums

type TokenType string

const (
	EmailVerification TokenType = "EmailVerification"
	PasswordReset     TokenType = "PasswordReset"
	Access            TokenType = "Access"
)
