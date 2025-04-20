package config

type Kafka interface {
	GetActivationTopic() string
	GetPasswordResetTopic() string
	GetClientID() string
	GetBrokers() []string
	GetVersion() string
	GetRetryMax() int
}

func (k kafka) GetActivationTopic() string {
	return k.Topics.ActivationEmail
}

func (k kafka) GetPasswordResetTopic() string {
	return k.Topics.PasswordResetEmail
}

func (k kafka) GetClientID() string {
	return k.ClientID
}

func (k kafka) GetBrokers() []string {
	return k.Brokers
}

func (k kafka) GetVersion() string {
	return k.Version
}

func (k kafka) GetRetryMax() int {
	return k.RetryMax
}
