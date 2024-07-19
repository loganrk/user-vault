package types

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
	Id       int    `gorm:"primarykey;size:16"`
	Username string `gorm:"username"`
	Password string `gorm:"password"`
	Name     string `gorm:"name"`
	State    int    `gorm:"state"`
	Status   int    `gorm:"status"`
}

type UserLoginAttempt struct {
	Id        int   `gorm:"primarykey;size:16"`
	UserId    int   `gorm:"user_id"`
	Timestamp int64 `gorm:"timestamp"`
}
