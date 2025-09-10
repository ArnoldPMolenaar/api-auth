package errors

// Define error codes as constants.
const (
	UsernameExists                         = "usernameExists"
	EmailExists                            = "emailExists"
	AppExists                              = "appExists"
	AppUnknown                             = "appUnknown"
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
	NoSelfDelete                           = "noSelfDelete"
	PermissionsEmpty                       = "permissionsEmpty"
	// Add more error codes as needed.
)
