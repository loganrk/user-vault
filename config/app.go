package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type App interface {
	GetPort() string
	IsMiddlewarePprofProperties() (bool, string)
	GetStoreDatabaseProperties() (string, string, string)
	GetStoreCacheDiskProperties() (bool, int)
	GetStoreCacheHeapProperties() (bool, int)
	GetEndpointCategoryProperties() (bool, string, string)
	GetEndpointProductProperties() (bool, string, string)
}

type app struct {
	port       string `yaml:"app"`
	middleware struct {
		pprof struct {
			enabled bool   `yaml:"enabled"`
			route   string `yaml:"route"`
		} `yaml:"pprof"`
	} `yaml:"middleware"`
	endpoint struct {
		category struct {
			enabled bool   `yaml:"enabled"`
			route   string `yaml:"route"`
			method  string `yaml:"method"`
		}
		product struct {
			enabled bool   `yaml:"enabled"`
			route   string `yaml:"route"`
			method  string `yaml:"method"`
		}
	} `yaml:"endpoint"`
	store struct {
		database struct {
			host     string `yaml:"host"`
			port     string `yaml:"port"`
			password string `yaml:"password"`
		} `yaml:"database"`
		cache struct {
			disk struct {
				enabled bool `yaml:"enabled"`
				expiry  int  `yaml:"expiry"`
			} `yaml:"disk"`
			heap struct {
				enabled bool `yaml:"enabled"`
				expiry  int  `yaml:"expiry"`
			} `yaml:"heap"`
		} `yaml:"cache"`
	} `yaml:"store"`
}

func InitApp(path string) (App, error) {

	configFile, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var appConfig app
	err = yaml.Unmarshal(configFile, &appConfig)
	if err != nil {
		return nil, err
	}

	return &appConfig, nil
}

func (c *app) GetPort() string {

	return c.port
}

func (c *app) IsMiddlewarePprofProperties() (bool, string) {
	pprof := c.middleware.pprof
	return pprof.enabled, pprof.route
}

func (c *app) GetStoreDatabaseProperties() (string, string, string) {
	database := c.store.database

	return database.host, database.port, database.password
}

func (c *app) GetStoreCacheDiskProperties() (bool, int) {
	diskCache := c.store.cache.disk

	return diskCache.enabled, diskCache.expiry
}

func (c *app) GetStoreCacheHeapProperties() (bool, int) {
	heapCache := c.store.cache.heap

	return heapCache.enabled, heapCache.expiry
}

func (c *app) GetEndpointCategoryProperties() (bool, string, string) {
	endpoint := c.endpoint.category

	return endpoint.enabled, endpoint.route, endpoint.method
}

func (c *app) GetEndpointProductProperties() (bool, string, string) {
	endpoint := c.endpoint.product

	return endpoint.enabled, endpoint.route, endpoint.method
}
