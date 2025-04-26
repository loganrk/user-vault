package kafka

import (
	"encoding/json"
	"fmt"
	"userVault/config"
	"userVault/internal/core/port"

	"github.com/IBM/sarama"
)

type kafkaMessager struct {
	appName            string
	producer           sarama.SyncProducer
	topicActivation    string
	topicPasswordReset string
}

// New initializes a new Kafka producer with client ID, version, and retry configuration.
// It returns a Messager adapter for publishing email-related events.
func New(appName string, broker []string, conf config.Kafka) (port.Messager, error) {
	kConfig := sarama.NewConfig()

	// Set client ID for Kafka tracing and logging
	kConfig.ClientID = conf.GetClientID()

	// Parse and apply Kafka protocol version
	version, err := sarama.ParseKafkaVersion(conf.GetVersion())
	if err != nil {
		return nil, fmt.Errorf("invalid Kafka version: %w", err)
	}
	kConfig.Version = version

	// Enable delivery reporting and retry settings
	kConfig.Producer.Return.Successes = true
	kConfig.Producer.Retry.Max = conf.GetRetryMax()

	producer, err := sarama.NewSyncProducer(broker, kConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka producer: %w", err)
	}

	return &kafkaMessager{
		appName:            appName,
		producer:           producer,
		topicActivation:    conf.GetActivationTopic(),
		topicPasswordReset: conf.GetPasswordResetTopic(),
	}, nil
}

// PublishActivationEmail sends a user activation email event to the Kafka topic.
func (k *kafkaMessager) PublishActivationEmail(toAddress, subject, name, link string) error {

	payload := struct {
		Type    string            `json:"type"`
		To      string            `json:"to"`
		Subject string            `json:"subject"`
		Macros  map[string]string `json:"macros"`
	}{
		Type:    "activation-email",
		To:      toAddress,
		Subject: subject,
		Macros: map[string]string{
			"name":           name,
			"activationLink": link,
			"appName":        k.appName,
		},
	}

	return k.publish(k.topicActivation, toAddress, payload)
}

// PublishPasswordResetEmail sends a password reset email event to the Kafka topic.
func (k *kafkaMessager) PublishPasswordResetEmail(toAddress, subject, name, link string) error {
	payload := struct {
		Type    string            `json:"type"`
		To      string            `json:"to"`
		Subject string            `json:"subject"`
		Macros  map[string]string `json:"macros"`
	}{
		Type:    "password-reset-email",
		To:      toAddress,
		Subject: subject,
		Macros: map[string]string{
			"name":           name,
			"activationLink": link,
			"appName":        k.appName,
		},
	}

	return k.publish(k.topicPasswordReset, toAddress, payload)
}

// publish marshals the payload and sends it to the specified Kafka topic with the given key.
func (k *kafkaMessager) publish(topic string, key string, payload any) error {
	value, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal message payload: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(value),
	}

	_, _, err = k.producer.SendMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to send Kafka message: %w", err)
	}

	return nil
}
