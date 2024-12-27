package responses

// Available struct for available response.
type Available struct {
	Available bool `json:"available"`
}

// SetAvailable func for create new Available struct.
func (a *Available) SetAvailable(available bool) {
	a.Available = available
}
