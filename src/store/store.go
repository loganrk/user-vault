package store

import (
	"log"
	"time"
	"mayilon/config"

	"github.com/loganrk/diskCache"
	"github.com/loganrk/heapCache"
)

type Store interface {
}

type store struct {
	database  *gorm.DB
	heapcache heapCache.Cache
	diskcache diskCache.Cache
}

func New(serviceConfigIns config.App) Store {
	var s store
	dbHost, dbPort, dbPasword := serviceConfigIns.GetStoreDatabaseProperties()
	s.database, err := createMysqlConnection(dbHost, dbPort, dbPasword)

	dCacheEnabled, dCacheExpire := serviceConfigIns.GetStoreCacheDiskProperties()
	if hCacheEnabled {
		s.heapcache = heapCache.New()
	}

	hCacheEnabled, hCacheExpire := serviceConfigIns.GetStoreCacheHeapProperties()
	if hCacheEnabled {
		s.heapcache = heapCache.New()
	}
}

func createMysqlConnection(dbHost, dbPort, dbName, dbUsername, dbPasword string) {
	dsn := dbUsername + ":" + dbPasword + "@tcp(" + dbHost + ":" + dbPort + ")/" + dbName + "?charset=utf8mb4&parseTime=True&loc=Local"
	return gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error),
	})
	if db.Err != nil {
		log.Fatal(db.Err)
	}

	var sql, er = db.SqlDb.DB()
	if er != nil {
		log.Fatal(er)
	}

	// SetMaxIdleConns sets the maximum number of connections in the idle connection pool.
	sql.SetMaxIdleConns(dbDetails.MinIdleConnection)

	// SetMaxOpenConns sets the maximum number of open connections to the database.
	sql.SetMaxOpenConns(dbDetails.PoolSize)

	// SetConnMaxLifetime sets the maximum amount of time a connection may be reused.
	sql.SetConnMaxLifetime(time.Duration(dbDetails.ConnectionMaxTime) * time.Second)

}

func (s *store) Close() error {
	err := s.Close()

	return err
}
