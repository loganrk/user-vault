package config

type app struct {
	Application struct {
		Name string `mapstructure:"name"`
		Port string `mapstructure:"port"`
	} `mapstructure:"application"`

	Logger logger `mapstructure:"logger"`

	Cipher struct {
		CryptoKey string `mapstructure:"crypto-key"`
	} `mapstructure:"cipher"`

	Middleware struct {
		Keys []string `mapstructure:"keys"`
	} `mapstructure:"middleware"`

	Store struct {
		Database struct {
			Host     string `mapstructure:"host"`
			Port     string `mapstructure:"port"`
			Username string `mapstructure:"username"`
			Password string `mapstructure:"password"`
			Name     string `mapstructure:"name"`
			Prefix   string `mapstructure:"prefix"`
		} `mapstructure:"database"`
	} `mapstructure:"store"`

	Token struct {
		JWT tokenJWT `mapstructure:"jwt"`
	} `mapstructure:"token"`

	User  user  `mapstructure:"user"`
	Kafka kafka `mapstructure:"kafka"`
}

type logger struct {
	Level    string `mapstructure:"level"`
	Encoding struct {
		Method string `mapstructure:"method"`
		Caller bool   `mapstructure:"caller"`
	} `mapstructure:"encoding"`
	Path    string `mapstructure:"path"`
	ErrPath string `mapstructure:"err-path"`
}

type user struct {
	MaxLoginAttempt           int    `mapstructure:"max-login-attempt"`
	LoginAttemptSessionPeriod int    `mapstructure:"login-attempt-session-period"`
	PasswordHashCost          int    `mapstructure:"password-hash-cost"`
	AppleClientId             string `mapstructure:"apple-client-id"`
	GoogleClientId            string `mapstructure:"google-client-id"`
	MicroSoftClientId         string `mapstructure:"microsoft-client-id"`

	Verification struct {
		Link        string `mapstructure:"link"`
		TokenExpiry int    `mapstructure:"token-expiry"`
	} `mapstructure:"verification"`

	PasswordReset struct {
		Link        string `mapstructure:"link"`
		TokenExpiry int    `mapstructure:"token-expiry"`
	} `mapstructure:"password-reset"`

	RefreshToken struct {
		Enabled  bool `mapstructure:"enabled"`
		Rotation bool `mapstructure:"rotation"`
		Expiry   int  `mapstructure:"expiry"`
	} `mapstructure:"refresh-token"`

	AccessToken struct {
		Expiry int `mapstructure:"expiry"`
	} `mapstructure:"access-token"`
}

type tokenJWT struct {
	Method            string `mapstructure:"method"`
	HmacKey           string `mapstructure:"hmac-key"`
	RsaPrivateKeyPath string `mapstructure:"rsa-private-key-path"`
	RsaPublicKeyPath  string `mapstructure:"rsa-public-key-path"`
}

type kafka struct {
	Brokers []string `mapstructure:"brokers"`
	Topics  struct {
		UserVerify        string `mapstructure:"user-verify"`
		UserPasswordReset string `mapstructure:"user-password-reset"`
	} `mapstructure:"topics"`
	ClientID string `mapstructure:"client-id"`
	Version  string `mapstructure:"version"`
	RetryMax int    `mapstructure:"retry-max"`
}
