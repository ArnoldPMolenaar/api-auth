package responses

import (
	"api-auth/main/src/models"
	"time"
)

type UserActivity struct {
	App         string     `json:"app"`
	LastLoginAt *time.Time `json:"lastLoginAt"`
}

type User struct {
	ID                uint           `json:"id"`
	Username          string         `json:"username"`
	Email             string         `json:"email"`
	PhoneNumber       *string        `json:"phoneNumber"`
	IsTempPassword    bool           `json:"isTempPassword"`
	EmailVerifiedAt   *time.Time     `json:"emailVerifiedAt"`
	PhoneVerifiedAt   *time.Time     `json:"phoneVerifiedAt"`
	PasswordChangedAt *time.Time     `json:"passwordChangedAt"`
	CreatedAt         time.Time      `json:"createdAt"`
	UpdatedAt         time.Time      `json:"updatedAt"`
	Roles             []AppRole      `json:"roles"`
	Recipes           []AppRecipe    `json:"recipes"`
	Activities        []UserActivity `json:"activities"`
}

// SetUser method to set user data from models.User{}.
func (u *User) SetUser(user *models.User) {
	u.ID = user.ID
	u.Username = user.Username
	u.Email = user.Email
	u.PhoneNumber = user.PhoneNumber
	u.IsTempPassword = user.IsTempPassword
	u.EmailVerifiedAt = func() *time.Time {
		if user.EmailVerifiedAt.Valid {
			return &user.EmailVerifiedAt.Time
		}
		return nil
	}()
	u.PhoneVerifiedAt = func() *time.Time {
		if user.PhoneVerifiedAt.Valid {
			return &user.PhoneVerifiedAt.Time
		}
		return nil
	}()
	u.PasswordChangedAt = func() *time.Time {
		if user.PasswordChangedAt.Valid {
			return &user.PasswordChangedAt.Time
		}
		return nil
	}()
	u.CreatedAt = user.CreatedAt
	u.UpdatedAt = user.UpdatedAt
	u.Roles = []AppRole{}
	u.Recipes = []AppRecipe{}
	u.Activities = []UserActivity{}

	// Set user roles.
	for i := range user.AppRoles {
		var roleFound bool
		for j := range u.Roles {
			if u.Roles[j].App == user.AppRoles[i].AppName && u.Roles[j].Role == user.AppRoles[i].RoleName {
				u.Roles[j].Permissions = append(u.Roles[j].Permissions, user.AppRoles[i].PermissionName)
				roleFound = true
				break
			}
		}

		if !roleFound {
			u.Roles = append(u.Roles, AppRole{
				App:         user.AppRoles[i].AppName,
				Role:        user.AppRoles[i].RoleName,
				Permissions: []string{user.AppRoles[i].PermissionName},
			})
		}
	}

	// Set user recipes.
	for i := range user.AppRecipes {
		u.Recipes = append(u.Recipes, AppRecipe{
			App:    user.AppRecipes[i].AppName,
			Recipe: user.AppRecipes[i].RecipeName,
		})
	}

	// Set user activity.
	for i := range user.AppActivity {
		u.Activities = append(u.Activities, UserActivity{
			App: user.AppActivity[i].AppName,
			LastLoginAt: func() *time.Time {
				if user.AppActivity[i].LastLoginAt.Valid {
					return &user.AppActivity[i].LastLoginAt.Time
				}
				return nil
			}(),
		})
	}
}
