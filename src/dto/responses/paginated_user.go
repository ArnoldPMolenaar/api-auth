package responses

import (
	"api-auth/main/src/models"
	"time"
)

type PaginatedUser struct {
	ID          uint       `json:"id"`
	Username    string     `json:"username"`
	Email       string     `json:"email"`
	PhoneNumber *string    `json:"phoneNumber"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	DeletedAt   *time.Time `json:"deletedAt"`
}

// SetPaginatedUser method to set user data from models.User{}.
func (u *PaginatedUser) SetPaginatedUser(user *models.User) {
	u.ID = user.ID
	u.Username = user.Username
	u.Email = user.Email
	u.PhoneNumber = user.PhoneNumber
	u.CreatedAt = user.CreatedAt
	u.UpdatedAt = user.UpdatedAt
	u.DeletedAt = func() *time.Time {
		if user.DeletedAt.Valid {
			return &user.DeletedAt.Time
		}
		return nil
	}()
}
