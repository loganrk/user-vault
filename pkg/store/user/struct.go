package user

import (
	"mayilon/pkg/config"

	"github.com/loganrk/go-db"
)

type userStore struct {
	db     db.DB
	tables config.Table
}
