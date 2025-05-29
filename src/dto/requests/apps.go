package requests

// Apps request DTO to get the names of all apps.
type Apps struct {
	Names []string `query:"appName"`
}
