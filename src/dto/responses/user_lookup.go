package responses

import "api-auth/main/src/models"

// UserLookup struct for user lookup response DTO.
type UserLookup struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// ToUserLookup converts the User Model to UserLookup DTO.
func (u *UserLookup) ToUserLookup(user *models.User) *UserLookup {
	u.ID = user.ID
	u.Username = user.Username
	u.Email = user.Email

	return u
}
