package responses

import (
	"api-auth/main/src/models"
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
	user models.User,
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

	for _, role := range user.AppRoles {
		u.Roles[role.RoleName] = make([]string, len(role.Role.Permissions))
		for _, permission := range role.Role.Permissions {
			u.Roles[role.RoleName] = append(u.Roles[role.RoleName], permission.Name)
		}
	}
}