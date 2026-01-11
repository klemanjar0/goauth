package kafka

const (
	EmailTopic = "emails"
)

type EmailJobType string

const (
	EmailJobVerification  EmailJobType = "verification"
	EmailJobPasswordReset EmailJobType = "password_reset"
	EmailJobWelcome       EmailJobType = "welcome"
)

type EmailJob struct {
	Type      EmailJobType `json:"type"`
	To        string       `json:"to"`
	Token     string       `json:"token,omitempty"`
	ExtraData string       `json:"extra_data,omitempty"`
}
