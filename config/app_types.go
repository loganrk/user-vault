package config

type app struct {
	Application struct {
		Name string `yaml:"name"`
		Port string `yaml:"port"`
	} `yaml:"application"`
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
	Api  api  `yaml:"api"`
	User user `yaml:"user"`
}

type api struct {
	UserLogin          apiData `yaml:"user_login"`
	UserRegister       apiData `yaml:"user_register"`
	UserActivation     apiData `yaml:"user_activation"`
	UserForgotPassword apiData `yaml:"user_forgot_password"`
	UserPasswordReset  apiData `yaml:"user_password_reset"`
}
type apiData struct {
	Enabled bool   `yaml:"enabled"`
	Route   string `yaml:"route"`
	Method  string `yaml:"method"`
}

type table struct {
	Prefix              string `yaml:"prefix"`
	User                string `yaml:"user"`
	UserLoginAttempt    string `yaml:"user_login_attempt"`
	UserActivationToken string `yaml:"user_activation_token"`
}

type user struct {
	MaxLoginAttempt           int `yaml:"max_login_attempt"`
	LoginAttemptSessionPeriod int `yaml:"login_attempt_session_period"`
	PasswordHashCost          int `yaml:"password_hash_cost"`
	Activation                struct {
		Link         string `yaml:"link"`
		LinkExpiry   int    `yaml:"link_expiry"`
		TemplatePath string `yaml:"template_path"`
	} `yaml:"activation"`
	PasswordReset struct {
		Link         string `yaml:"link"`
		LinkExpiry   int    `yaml:"link_expiry"`
		TemplatePath string `yaml:"template_path"`
	} `yaml:"password_reset"`
}
