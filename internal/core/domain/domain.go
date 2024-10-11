package domain

import (
	"context"
	"time"
)

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
	Token     string    `gorm:"column:token;size:255"`
	Revoked   bool      `gorm:"column:revoked"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
	CreatedAt time.Time `gorm:"autoCreateTime;column:created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime;column:updated_at"`
}

type List struct {
	User UserSvr
}

type UserSvr interface {
	GetUserByUserid(ctx context.Context, userid int) (User, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	CheckLoginFailedAttempt(ctx context.Context, userId int) (int, error)
	CreateLoginAttempt(ctx context.Context, userId int, success bool) (int, error)
	CheckPassword(ctx context.Context, password string, passwordHash string, saltHash string) (bool, error)
	CreateUser(ctx context.Context, username, password, name string) (int, error)

	CreateActivationToken(ctx context.Context, userid int) (int, string, error)
	GetActivationLink(tokenId int, token string) string
	GetActivationEmailTemplate(ctx context.Context, name string, activationLink string) (string, error)
	SendActivation(ctx context.Context, email string, template string) error
	GetUserActivationByToken(ctx context.Context, token string) (UserActivationToken, error)
	UpdatedActivationtatus(ctx context.Context, tokenId int, status int) error
	UpdateStatus(ctx context.Context, userid int, status int) error

	CreatePasswordResetToken(ctx context.Context, userid int) (int, string, error)
	GetPasswordResetLink(token string) string
	GetPasswordResetEmailTemplate(ctx context.Context, name string, passwordResetLink string) (string, error)
	SendPasswordReset(ctx context.Context, email string, template string) error
	GetPasswordResetByToken(ctx context.Context, token string) (UserPasswordReset, error)
	UpdatedPasswordResetStatus(ctx context.Context, tokenid int, status int) error
	UpdatePassword(ctx context.Context, userid int, password string, saltHash string) error

	RefreshTokenEnabled() bool
	RefreshTokenRotationEnabled() bool
	StoreRefreshToken(ctx context.Context, userid int, token string, expiresAt time.Time) (int, error)
	RevokedRefreshToken(ctx context.Context, userid int, refreshToken string) error
	GetRefreshTokenData(ctx context.Context, userid int, token string) (UserRefreshToken, error)
}
