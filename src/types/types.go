package types

const (
	LOGIN_ATTEMPT_PROCEED     = 1
	LOGIN_ATTEMPT_MAX_REACHED = 2
	LOGIN_ATTEMPT_NOT_PROCEED = 3
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
	Id        int `gorm:"primarykey;size:16"`
	UserId    int `gorm:"user_id"`
	Timestamp int `gorm:"timestamp"`
}
