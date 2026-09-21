package domain

type Consent struct {
	TermID   string `json:"termId"`
	Accepted bool   `json:"accepted"`
}

type Signup struct {
	Email, Nickname, PasswordHash string
}
