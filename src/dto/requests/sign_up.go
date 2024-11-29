package requests

// SignUp struct for username password signup request.
type SignUp struct {
	App         string   `json:"app" validate:"required"`
	Username    string   `json:"username" validate:"required"`
	Email       string   `json:"email" validate:"required,email"`
	PhoneNumber *string  `json:"phoneNumber"`
	Password    string   `json:"password"`
	Roles       []string `json:"roles"`
	Recipes     []string `json:"recipes"`
}
