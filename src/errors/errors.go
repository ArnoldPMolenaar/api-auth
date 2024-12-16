package errors

// Define error codes as constants.
const (
	UsernameExists                         = "usernameExists"
	EmailExists                            = "emailExists"
	AppExists                              = "appExists"
	PhoneNumberExists                      = "phoneNumberExists"
	UsernameEmailUnknown                   = "usernameEmailUnknown"
	EmailUnknown                           = "emailUnknown"
	RecipeNotAllowed                       = "recipeNotAllowed"
	PasswordIncorrect                      = "passwordIncorrect"
	TokenCreate                            = "tokenCreate"
	TokenRefreshInvalid                    = "tokenRefreshInvalid"
	TokenNoBearerAuthorizationHeaderFormat = "tokenNoBearerAuthorizationHeaderFormat"
	TokenExtraction                        = "tokenExtraction"
	InvalidPassword                        = "invalidPassword"
	// Add more error codes as needed.
)
