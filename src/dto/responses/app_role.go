package responses

type AppRole struct {
	App         string   `json:"app" validate:"required"`
	Role        string   `json:"role" validate:"required"`
	Permissions []string `json:"permissions" validate:"required"`
}
