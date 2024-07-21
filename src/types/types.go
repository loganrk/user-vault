package types

import "time"

const (
	LOGIN_ATTEMPT_SUCCESS     = 1
	LOGIN_ATTEMPT_MAX_REACHED = 2
	LOGIN_ATTEMPT_FAILED      = 3

	USER_STATUS_ACTIVE   = 1
	USER_STATUS_INACTIVE = 2
	USER_STATUS_PENDING  = 3
	USER_STATUS_BANNED   = 4

	USER_STATE_INITIAL = 1

	EMAIL_STATUS_SUCCESS = 1
	EMAIL_STATUS_FAILED  = 2
)

type User struct {
	Id        int       `gorm:"primarykey;size:16"`
	Username  string    `gorm:"username"`
	Password  string    `gorm:"password"`
	Name      string    `gorm:"name"`
	Salt      string    `gorm:"salt"`
	State     int       `gorm:"state"`
	Status    int       `gorm:"status"`
	CreatedAt time.Time `gorm:"created_at"`
	UpdatedAt time.Time `gorm:"updated_at"`
}

type UserLoginAttempt struct {
	Id        int       `gorm:"primarykey;size:16"`
	UserId    int       `gorm:"user_id"`
	Success   bool      `gorm:"success"`
	Timestamp int64     `gorm:"timestamp"`
	CreatedAt time.Time `gorm:"created_at"`
}

type UserActivationToken struct {
	Id        int       `gorm:"primarykey;size:16"`
	UserId    int       `gorm:"user_id"`
	Token     string    `gorm:"token"`
	CreatedAt time.Time `gorm:"created_at"`
	ExpiredAt time.Time `gorm:"expired_at"`
}
