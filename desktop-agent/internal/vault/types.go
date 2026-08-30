package vault

type Credential struct {
	ID       string `json:"id"`
	Origin   string `json:"origin"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type ExistsResponse struct {
	Exists bool `json:"exists"`
}
