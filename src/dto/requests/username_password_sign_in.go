package requests

// UsernamePasswordSignIn struct for username password sign-in request.
type UsernamePasswordSignIn struct {
	App      string `json:"app"`
	Username string `json:"username"`
	Password string `json:"password"`
}
