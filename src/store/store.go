package store

import "mayilon/src/types"

type User interface {
	CreateUser(user types.User) error
	GetUserByID(id int) (types.User, error)
	GetUserByUsernamePassword(username, password string) (types.User, error)
}
