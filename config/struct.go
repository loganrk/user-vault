package config

type app struct {
	Application struct {
		Name string `mapstructure:"name"`
		Port string `mapstructure:"port"`
	} `mapstructure:"application"`
	Logger logger `mapstructure:"logger"`
	Cipher struct {
		CryptoKey string `mapstructure:"cryptoKey"`
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
	Api   api   `mapstructure:"api"`
	User  user  `mapstructure:"user"`
	Kafka kafka `mapstructure:"kafka"`
}

type logger struct {
	Level    string
	Encoding struct {
		Method string
		Caller bool
	}
	Path    string
	ErrPath string
}

type api struct {
	UserLogin            apiData `mapstructure:"userLogin"`
	UserOAuthLogin       apiData `mapstructure:"userOAuthLogin"`
	UserRegister         apiData `mapstructure:"userRegister"`
	UserActivation       apiData `mapstructure:"userActivation"`
	UserResendActivation apiData `mapstructure:"userResendActivation"`
	UserForgotPassword   apiData `mapstructure:"userForgotPassword"`
	UserPasswordReset    apiData `mapstructure:"userPasswordReset"`
	UserRefreshToken     apiData `mapstructure:"userRefreshToken"`
	UserLogout           apiData `mapstructure:"userLogout"`
}
type apiData struct {
	Enabled bool   `mapstructure:"enabled"`
	Route   string `mapstructure:"route"`
	Method  string `mapstructure:"method"`
}

type user struct {
	MaxLoginAttempt           int `mapstructure:"maxLoginAttempt"`
	LoginAttemptSessionPeriod int `mapstructure:"loginAttemptSessionPeriod"`
	PasswordHashCost          int `mapstructure:"passwordHashCost"`
	Activation                struct {
		TokenExpiry int `mapstructure:"tokenExpiry"`
	} `mapstructure:"activation"`
	PasswordReset struct {
		TokenExpiry int `mapstructure:"tokenExpiry"`
	} `mapstructure:"passwordReset"`
	RefreshToken struct {
		Enabled  bool `mapstructure:"enabled"`
		Rotation bool `mapstructure:"rotation"`
		Expiry   int  `mapstructure:"expiry"`
	} `mapstructure:"refreshToken"`
	AccessToken struct {
		Expiry int `mapstructure:"expiry"`
	} `mapstructure:"accessToken"`
}

type tokenJWT struct {
	Method            string `mapstructure:"method"`
	HmacKey           string `mapstructure:"hmacKey"`
	RsaPrivateKeyPath string `mapstructure:"rsaPrivateKeyPath"`
	RsaPublicKeyPath  string `mapstructure:"rsaPublicKeyPath"`
}

type kafka struct {
	Brokers []string `mapstructure:"brokers"`
	Topics  struct {
		UserActivation    string `mapstructure:"userActivation"`
		UserPasswordReset string `mapstructure:"userPasswordReset"`
	} `mapstructure:"topics"`
	ClientID string `mapstructure:"clientID"`
	Version  string `mapstructure:"version"`
	RetryMax int    `mapstructure:"retryMax"`
}
