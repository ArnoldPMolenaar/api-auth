package claims

// IdentityClaims struct to hold the identity of the user and app.
type IdentityClaims struct {
	Id  int    `json:"id"`
	App string `json:"app"`
}
