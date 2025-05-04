package config

type Kafka interface {
	GetVerificationTopic() string
	GetPasswordResetTopic() string
	GetClientID() string
	GetBrokers() []string
	GetVersion() string
	GetRetryMax() int
}

func (k kafka) GetVerificationTopic() string {
	return k.Topics.UserVerify
}

func (k kafka) GetPasswordResetTopic() string {
	return k.Topics.UserVerify
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
