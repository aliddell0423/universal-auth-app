package model

type Credential struct {
	ID        string `json:"id"`
	Origin    string `json:"origin"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type CredentialMeta struct {
	ID        string `json:"id"`
	Origin    string `json:"origin"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type CredentialInput struct {
	Origin   string `json:"origin"`
	Username string `json:"username"`
	Password string `json:"password"`
}
