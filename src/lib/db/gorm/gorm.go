package gorm

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type db struct {
	dialer *gorm.DB
}

func New(hostname, port, username, password, name string) (*db, error) {
	dsn := username + ":" + password + "@tcp(" + hostname + ":" + port + ")/" + name + "?charset=utf8mb4&parseTime=True&loc=Local"
	dialer, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error),
	})

	return &db{
		dialer: dialer,
	}, err

}

func (dbData *db) GetDb() *gorm.DB {
	return dbData.dialer
}
