package responses

import (
	"api-auth/main/src/models"
	"api-auth/main/src/utils"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type UsernamePasswordSignIn struct {
	ID              uint                `json:"id"`
	Username        string              `json:"username"`
	Email           string              `json:"email"`
	PhoneNumber     *string             `json:"phoneNumber"`
	IsTempPassword  bool                `json:"isTempPassword"`
	EmailVerifiedAt *time.Time          `json:"emailVerifiedAt"`
	PhoneVerifiedAt *time.Time          `json:"phoneVerifiedAt"`
	CreatedAt       time.Time           `json:"createdAt"`
	UpdatedAt       time.Time           `json:"updatedAt"`
	AccessToken     Token               `json:"accessToken"`
	RefreshToken    Token               `json:"refreshToken"`
	Roles           map[string][]string `json:"roles"`
}

// SetUsernamePasswordSignIn method to set username password sign-in response from user model.
func (u *UsernamePasswordSignIn) SetUsernamePasswordSignIn(
	user *models.User,
	accessToken string,
	accessTokenExpiresAt *jwt.NumericDate,
	refreshToken *models.UserAppRefreshToken) {
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
	u.CreatedAt = user.CreatedAt
	u.UpdatedAt = user.UpdatedAt
	u.AccessToken = Token{
		Token:     accessToken,
		ExpiresAt: accessTokenExpiresAt.Time,
	}
	u.RefreshToken = Token{
		Token:     refreshToken.Token,
		ExpiresAt: refreshToken.ValidUntil,
	}
	u.Roles = map[string][]string{}

	for i := range user.AppRoles {
		var roleName = utils.PascalCaseToCamelcase(user.AppRoles[i].RoleName)
		u.Roles[roleName] = []string{}
		for j := range user.AppRoles[i].Role.Permissions {
			u.Roles[roleName] = append(u.Roles[roleName], user.AppRoles[i].Role.Permissions[j].Name)
		}
	}
}
