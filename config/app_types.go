package config

type app struct {
	port       string `yaml:"app"`
	middleware struct {
	} `yaml:"middleware"`
	api struct {
		userLogin          api `yaml:"user_login"`
		userRegister       api `yaml:"user_register"`
		userForgotPassword api `yaml:"user_forgot_password"`
		userResetPassword  api `yaml:"user_reset_password"`
	} `yaml:"api"`
	store struct {
		database struct {
			host     string `yaml:"host"`
			port     string `yaml:"port"`
			username string `yaml:"username"`
			password string `yaml:"password"`
			name     string `yaml:"name"`
			tables   struct {
				user string `yaml:"user"`
			} `yaml:"tables"`
		} `yaml:"database"`
		cache struct {
			heap struct {
				enabled     bool `yaml:"enabled"`
				maxCapacity int  `yaml:"max_capacity"`
				expiry      int  `yaml:"expiry"`
			} `yaml:"heap"`
		} `yaml:"cache"`
	} `yaml:"store"`
}

type api struct {
	enabled bool   `yaml:"enabled"`
	route   string `yaml:"route"`
	method  string `yaml:"method"`
}
