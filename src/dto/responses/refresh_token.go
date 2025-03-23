package responses

import (
	"api-auth/main/src/models"
	"github.com/golang-jwt/jwt/v5"
)

// RefreshToken struct to hold refresh token response data.
type RefreshToken struct {
	AccessToken  Token  `json:"accessToken"`
	RefreshToken *Token `json:"refreshToken"`
}

// SetAccessToken method to set access token in refresh token response from access token and access token expires at.
func (r *RefreshToken) SetAccessToken(accessToken string, accessTokenExpiresAt *jwt.NumericDate) {
	r.AccessToken = Token{}
	r.AccessToken.SetToken(accessToken, accessTokenExpiresAt.Time)
}

// SetRefreshToken method to set refresh token response from refresh token data model.
func (r *RefreshToken) SetRefreshToken(refreshToken *models.UserAppRefreshToken) {
	if refreshToken == nil {
		return
	}

	r.RefreshToken = &Token{}
	r.RefreshToken.SetToken(refreshToken.Token, refreshToken.ValidUntil)
}
