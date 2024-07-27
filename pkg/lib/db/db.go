package db

import (
	igorm "mayilon/pkg/lib/db/gorm"

	"gorm.io/gorm"
)

type Config struct {
	Host     string
	Port     string
	Username string
	Password string
	Name     string
}
type DB interface {
	GetDb() *gorm.DB
}

func New(conf Config) (DB, error) {
	return igorm.New(conf.Host, conf.Port, conf.Username, conf.Password, conf.Name)

}
