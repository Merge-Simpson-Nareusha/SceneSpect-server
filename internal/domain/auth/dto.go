package auth

type SignupStartResult struct {
	SignupSessionID string
	Email           string
	Nickname        string
	ExpiresIn       int64
}

type VerificationResult struct {
	ExpiresIn   int64
	ResendAfter int64
}

type AccountLookupResult struct {
	Email    string
	Username string
}

type signupStartRequest struct {
	Email string `json:"email" binding:"required"`
}

type passwordRequest struct {
	SignupSessionID      string `json:"signupSessionId" binding:"required"`
	Password             string `json:"password" binding:"required"`
	PasswordConfirmation string `json:"passwordConfirmation" binding:"required"`
}

type sessionRequest struct {
	SignupSessionID string `json:"signupSessionId" binding:"required"`
}

type verifyRequest struct {
	SignupSessionID string `json:"signupSessionId" binding:"required"`
	Code            string `json:"code" binding:"required"`
}

type consentRequest struct {
	SignupSessionID string    `json:"signupSessionId" binding:"required"`
	Consents        []Consent `json:"consents" binding:"required"`
}

type loginRequest struct {
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type emailRequest struct {
	Email string `json:"email" binding:"required"`
}

type resetRequest struct {
	Token                string `json:"token" binding:"required"`
	Password             string `json:"password" binding:"required"`
	PasswordConfirmation string `json:"passwordConfirmation" binding:"required"`
}

type findRequest struct {
	Login string `json:"login" binding:"required"`
}
