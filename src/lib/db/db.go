package db

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm/logger"

	"gorm.io/gorm"
)

type Config struct {
	Host     string
	Port     string
	Username string
	Password string
	Name     string
}

func New(conf Config) (*gorm.DB, error) {
	dsn := conf.Username + ":" + conf.Password + "@tcp(" + conf.Host + ":" + conf.Port + ")/" + conf.Name + "?charset=utf8mb4&parseTime=True&loc=Local"
	return gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error),
	})

}
