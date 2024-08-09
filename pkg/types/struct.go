package types

import "time"

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
	CreatedAt time.Time `gorm:"created_at"`
}

type UserActivationToken struct {
	Id        int       `gorm:"primarykey;size:16"`
	UserId    int       `gorm:"user_id"`
	Token     string    `gorm:"token"`
	Status    int       `gorm:"status"`
	CreatedAt time.Time `gorm:"created_at"`
	ExpiresAt time.Time `gorm:"expires_at"`
}

type UserPasswordReset struct {
	Id        int       `gorm:"primarykey;size:16"`
	UserId    int       `gorm:"user_id"`
	Token     string    `gorm:"token"`
	Status    int       `gorm:"status"`
	CreatedAt time.Time `gorm:"created_at"`
	ExpiresAt time.Time `gorm:"expires_at"`
}

type UserRefreshToken struct {
	Id        int       `gorm:"primarykey;size:16"`
	UserId    int       `gorm:"user_id"`
	Token     string    `gorm:"token"`
	CreatedAt time.Time `gorm:"created_at"`
	ExpiresAt time.Time `gorm:"expires_at"`
	Revoked   bool      `gorm:"revoked"`
}
