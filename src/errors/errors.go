package errors

// Define error codes as constants.
const (
	BodyParse                              = "bodyParse"
	Validator                              = "validator"
	QueryError                             = "queryError"
	CacheError                             = "cacheError"
	UsernameExists                         = "usernameExists"
	EmailExists                            = "emailExists"
	AppExists                              = "appExists"
	PhoneNumberExists                      = "phoneNumberExists"
	UsernameEmailUnknown                   = "usernameEmailUnknown"
	RecipeNotAllowed                       = "recipeNotAllowed"
	PasswordIncorrect                      = "passwordIncorrect"
	TokenCreate                            = "tokenCreate"
	TokenRefreshInvalid                    = "tokenRefreshInvalid"
	TokenNoBearerAuthorizationHeaderFormat = "tokenNoBearerAuthorizationHeaderFormat"
	TokenExtraction                        = "tokenExtraction"
	Forbidden                              = "forbidden"
	MissingRequiredParam                   = "missingRequiredParam"
	InvalidParam                           = "invalidParam"
	OutOfSync                              = "outOfSync"
	InvalidPassword                        = "invalidPassword"
	// Add more error codes as needed.
)
