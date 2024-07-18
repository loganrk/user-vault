package config

type app struct {
	Port       string `yaml:"port"`
	Middleware struct {
		Authorization struct {
			Enabled bool   `yaml:"enabled"`
			Token   string `yaml:"token"`
		} `yaml:"authorization"`
		Authentication struct {
			SecretKey   string `yaml:"secret_key"`
			TokenExpiry int    `yaml:"token_expiry"`
		} `yaml:"authentication"`
	} `yaml:"middleware"`
	Api struct {
		UserLogin          api `yaml:"user_login"`
		UserRegister       api `yaml:"user_register"`
		UserForgotPassword api `yaml:"user_forgot_password"`
		UserResetPassword  api `yaml:"user_reset_password"`
	} `yaml:"api"`
	Store struct {
		Database struct {
			Host     string `yaml:"host"`
			Port     string `yaml:"port"`
			Username string `yaml:"username"`
			Password string `yaml:"password"`
			Name     string `yaml:"name"`
			Table    table  `yaml:"table"`
		} `yaml:"database"`
		Cache struct {
			Heap struct {
				Enabled     bool `yaml:"enabled"`
				MaxCapacity int  `yaml:"max_capacity"`
				Expiry      int  `yaml:"expiry"`
			} `yaml:"heap"`
		} `yaml:"cache"`
	} `yaml:"store"`
	User user
}

type api struct {
	Enabled bool   `yaml:"enabled"`
	Route   string `yaml:"route"`
	Method  string `yaml:"method"`
}

type table struct {
	Prefix           string `yaml:"prefix"`
	User             string `yaml:"user"`
	UserLoginAttempt string `yaml:"user_login_attempt"`
}

type user struct {
	MaxLoginAttempt           int `yaml:"max_login_attempt"`
	LoginAttemptSessionPeriod int `yaml:"login_attempt_session_period"`
}
