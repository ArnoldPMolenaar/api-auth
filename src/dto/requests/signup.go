package requests

// Signup struct for username password signup request.
type Signup struct {
	App         string   `json:"app"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	PhoneNumber *string  `json:"phoneNumber"`
	Password    string   `json:"password"`
	Roles       []string `json:"roles"`
	Recipes     []string `json:"recipes"`
}
