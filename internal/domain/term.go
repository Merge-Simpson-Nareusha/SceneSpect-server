package domain

type Term struct {
	ID       string `json:"id"`
	Code     string `json:"code"`
	Version  string `json:"version"`
	Title    string `json:"title"`
	Content  string `json:"content"`
	Required bool   `json:"required"`
}
