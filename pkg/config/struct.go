package config

type app struct {
	Application struct {
		Name string `mapstructure:"name"`
		Port string `mapstructure:"port"`
	} `mapstructure:"application"`
	Chipper struct {
		CryptoKey string `mapstructure:"cryptoKey"`
	} `mapstructure:"chipper"`
	Middleware struct {
		Authorization struct {
			Enabled bool   `mapstructure:"enabled"`
			Token   string `mapstructure:"token"`
		} `mapstructure:"authorization"`
		Authentication struct {
			TokenExpiry int `mapstructure:"tokenExpiry"`
		} `mapstructure:"authentication"`
	} `mapstructure:"middleware"`
	Store struct {
		Database struct {
			Host     string `mapstructure:"host"`
			Port     string `mapstructure:"port"`
			Username string `mapstructure:"username"`
			Password string `mapstructure:"password"`
			Name     string `mapstructure:"name"`
			Table    table  `mapstructure:"table"`
		} `mapstructure:"database"`
		Cache struct {
			Heap struct {
				Enabled     bool `mapstructure:"enabled"`
				MaxCapacity int  `mapstructure:"max_capacity"`
				Expiry      int  `mapstructure:"expiry"`
			} `mapstructure:"heap"`
		} `mapstructure:"cache"`
	} `mapstructure:"store"`
	Api  api  `mapstructure:"api"`
	User user `mapstructure:"user"`
}

type api struct {
	UserLogin          apiData `mapstructure:"userLogin"`
	UserRegister       apiData `mapstructure:"userRegister"`
	UserActivation     apiData `mapstructure:"userActivation"`
	UserForgotPassword apiData `mapstructure:"userForgotPassword"`
	UserPasswordReset  apiData `mapstructure:"userPasswordReset"`
}
type apiData struct {
	Enabled bool   `mapstructure:"enabled"`
	Route   string `mapstructure:"route"`
	Method  string `mapstructure:"method"`
}

type table struct {
	Prefix              string `mapstructure:"prefix"`
	User                string `mapstructure:"user"`
	UserLoginAttempt    string `mapstructure:"userLoginAttempt"`
	UserActivationToken string `mapstructure:"userActivationToken"`
	UserPasswordReset   string `mapstructure:"userPasswordReset"`
}

type user struct {
	MaxLoginAttempt           int `mapstructure:"maxLoginAttempt"`
	LoginAttemptSessionPeriod int `mapstructure:"loginAttemptSessionPeriod"`
	PasswordHashCost          int `mapstructure:"passwordHashCost"`
	Activation                struct {
		Link         string `mapstructure:"link"`
		LinkExpiry   int    `mapstructure:"linkExpiry"`
		TemplatePath string `mapstructure:"templatePath"`
	} `mapstructure:"activation"`
	PasswordReset struct {
		Link         string `mapstructure:"link"`
		LinkExpiry   int    `mapstructure:"linkExpiry"`
		TemplatePath string `mapstructure:"templatePath"`
	} `mapstructure:"passwordReset"`
}
