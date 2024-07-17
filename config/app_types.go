package config

type app struct {
	Port       string `yaml:"port"`
	Middleware struct {
		Auth struct {
			Enabled bool   `yaml:"enabled"`
			Token   string `yaml:"token"`
		} `yaml:"auth"`
	} `yaml:"middleware"`
	Api struct {
		UserLogin          api `yaml:"user_login"`
		UserRegister       api `yaml:"user_register"`
		UserForgotPassword api `yaml:"user_forgot_password"`
		UserResetPassword  api `yaml:"user_reset_password"`
	} `yaml:"api"`
	Store struct {
		Database struct {
			Host        string `yaml:"host"`
			Port        string `yaml:"port"`
			Username    string `yaml:"username"`
			Password    string `yaml:"password"`
			TablePrefix string `yaml:"table_prefix"`
			Name        string `yaml:"name"`
			Tables      struct {
				User string `yaml:"user"`
			} `yaml:"tables"`
		} `yaml:"database"`
		Cache struct {
			Heap struct {
				Enabled     bool `yaml:"enabled"`
				MaxCapacity int  `yaml:"max_capacity"`
				Expiry      int  `yaml:"expiry"`
			} `yaml:"heap"`
		} `yaml:"cache"`
	} `yaml:"store"`
}

type api struct {
	Enabled bool   `yaml:"enabled"`
	Route   string `yaml:"route"`
	Method  string `yaml:"method"`
}
