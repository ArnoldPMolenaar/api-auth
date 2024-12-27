package responses

import "api-auth/main/src/models"

// SignUp struct for username password signup response.
type SignUp struct {
	ID          uint        `json:"id"`
	Username    string      `json:"username"`
	Email       string      `json:"email"`
	PhoneNumber *string     `json:"phoneNumber"`
	Password    string      `json:"password"`
	Roles       []AppRole   `json:"roles"`
	Recipes     []AppRecipe `json:"recipes"`
}

// SetSignUp method to set signup response from user model.
func (u *SignUp) SetSignUp(user *models.User) {
	u.ID = user.ID
	u.Username = user.Username
	u.Email = user.Email
	u.PhoneNumber = user.PhoneNumber
	u.Roles = []AppRole{}
	u.Recipes = []AppRecipe{}

	// Set user roles.
	for i := range user.AppRoles {
		u.Roles = append(u.Roles, AppRole{
			App:  user.AppRoles[i].AppName,
			Role: user.AppRoles[i].RoleName,
		})
	}

	// Set user recipes.
	for i := range user.AppRecipes {
		u.Recipes = append(u.Recipes, AppRecipe{
			App:    user.AppRecipes[i].AppName,
			Recipe: user.AppRecipes[i].RecipeName,
		})
	}
}
