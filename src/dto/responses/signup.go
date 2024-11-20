package responses

import "api-auth/main/src/models"

// Signup struct for username password signup response.
type Signup struct {
	ID          uint     `json:"id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	PhoneNumber *string  `json:"phoneNumber"`
	Password    string   `json:"password"`
	Roles       []string `json:"roles"`
	Recipes     []string `json:"recipes"`
}

// SetSignup method to set signup response from user model.
func (u *Signup) SetSignup(user models.User) {
	u.ID = user.ID
	u.Username = user.Username
	u.Email = user.Email
	u.PhoneNumber = user.PhoneNumber
	u.Roles = []string{}
	u.Recipes = []string{}

	for _, role := range user.AppRoles {
		u.Roles = append(u.Roles, role.RoleName)
	}

	for _, recipe := range user.AppRecipes {
		u.Recipes = append(u.Recipes, recipe.RecipeName)
	}
}
