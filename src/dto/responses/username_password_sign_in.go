package responses

import (
	"api-auth/main/src/models"
	util "github.com/ArnoldPMolenaar/api-utils/utils"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type UsernamePasswordSignIn struct {
	ID              uint                           `json:"id"`
	Username        string                         `json:"username"`
	Email           string                         `json:"email"`
	PhoneNumber     *string                        `json:"phoneNumber"`
	IsTempPassword  bool                           `json:"isTempPassword"`
	EmailVerifiedAt *time.Time                     `json:"emailVerifiedAt"`
	PhoneVerifiedAt *time.Time                     `json:"phoneVerifiedAt"`
	CreatedAt       time.Time                      `json:"createdAt"`
	UpdatedAt       time.Time                      `json:"updatedAt"`
	AccessToken     Token                          `json:"accessToken"`
	Apps            map[string]map[string][]string `json:"apps"`
}

// SetUsernamePasswordSignIn method to set username password sign-in response from user model.
func (u *UsernamePasswordSignIn) SetUsernamePasswordSignIn(
	user *models.User,
	accessToken string,
	accessTokenExpiresAt *jwt.NumericDate) {
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
	u.Apps = map[string]map[string][]string{}

	for i := range user.AppRoles {
		var appName = util.PascalCaseToCamelcase(user.AppRoles[i].AppName)
		var roleName = util.PascalCaseToCamelcase(user.AppRoles[i].RoleName)
		if _, ok := u.Apps[appName]; !ok {
			u.Apps[appName] = map[string][]string{}
		}
		if _, ok := u.Apps[appName][roleName]; !ok {
			u.Apps[appName][roleName] = []string{}
		}

		u.Apps[appName][roleName] = append(u.Apps[appName][roleName], user.AppRoles[i].PermissionName)
	}
}
