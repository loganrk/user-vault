package user

import "mayilon/pkg/lib/db"

type userStore struct {
	db db.DB
	//cache heap.Cache
	tables
}

type tables struct {
	user                string
	userLoginAttempt    string
	userActivationToken string
	userPasswordReset   string
}
