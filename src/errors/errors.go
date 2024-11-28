package errors

// Define error codes as constants.
const (
	BodyParse            = "bodyParse"
	Validator            = "validator"
	QueryError           = "queryError"
	CacheError           = "cacheError"
	PasswordEmpty        = "passwordEmpty"
	UsernameExists       = "usernameExists"
	EmailExists          = "emailExists"
	PhoneNumberExists    = "phoneNumberExists"
	UsernameEmailUnknown = "usernameEmailUnknown"
	RecipeNotAllowed     = "recipeNotAllowed"
	PasswordIncorrect    = "passwordIncorrect"
	TokenCreate          = "tokenCreate"
	// Add more error codes as needed.
)
