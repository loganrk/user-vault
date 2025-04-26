package domain

import "time"

type User struct {
	Id        int       `gorm:"primarykey;size:16"`
	Username  string    `gorm:"column:username;size:255"`
	Password  string    `gorm:"column:password;size:255"`
	Name      string    `gorm:"column:name;size:255"`
	Salt      string    `gorm:"column:salt;size:255"`
	State     int       `gorm:"column:state;size:11;default:1"`
	Status    int       `gorm:"column:status;size:11;default:3"`
	CreatedAt time.Time `gorm:"autoCreateTime,column:created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime,column:updated_at"`
}

type UserLoginAttempt struct {
	Id        int       `gorm:"primarykey;size:16"`
	UserId    int       `gorm:"column:user_id;size:16"`
	Success   bool      `gorm:"column:success"`
	CreatedAt time.Time `gorm:"autoCreateTime;column:created_at"`
}

type UserActivationToken struct {
	Id        int       `gorm:"primarykey;size:16"`
	UserId    int       `gorm:"column:user_id;size:16"`
	Token     string    `gorm:"column:token;size:255"`
	Status    int       `gorm:"column:status;size:16"`
	CreatedAt time.Time `gorm:"autoCreateTime;column:created_at"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
}

type UserPasswordReset struct {
	Id        int       `gorm:"primarykey;size:16"`
	UserId    int       `gorm:"column:user_id;size:16"`
	Token     string    `gorm:"column:token;size:255"`
	Status    int       `gorm:"column:status;size:16;default:1"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
	CreatedAt time.Time `gorm:"autoCreateTime;column:created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime;column:updated_at"`
}

type UserRefreshToken struct {
	Id        int       `gorm:"primarykey;size:16"`
	UserId    int       `gorm:"column:user_id;size:16"`
	Token     string    `gorm:"column:token;size:1055"`
	Revoked   bool      `gorm:"column:revoked"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
	CreatedAt time.Time `gorm:"autoCreateTime;column:created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime;column:updated_at"`
}
