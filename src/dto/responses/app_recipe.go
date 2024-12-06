package responses

type AppRecipe struct {
	App    string `json:"app" validate:"required"`
	Recipe string `json:"recipe" validate:"required"`
}
