package domain

import "time"

type User struct {
	Id            int       `gorm:"primarykey"`
	Email         string    `gorm:"column:email;size:255"`
	EmailVerified bool      `gorm:"column:email_verified;default:false"`
	Phone         string    `gorm:"column:phone;size:255"`
	PhoneVerified bool      `gorm:"column:phone_verified;default:false"`
	Password      string    `gorm:"column:password;size:255"`
	Name          string    `gorm:"column:name;size:255"`
	State         int       `gorm:"column:state;not null;default:1"`
	Status        int       `gorm:"column:status;not null;default:3"`
	CreatedAt     time.Time `gorm:"autoCreateTime,column:created_at"`
	UpdatedAt     time.Time `gorm:"autoUpdateTime,column:updated_at"`
}

type OAuthAccount struct {
	Id         int       `gorm:"column:id;type:uuid;primaryKey"`
	UserId     int       `gorm:"column:user_id;"`
	Provider   OAuthID   `gorm:"column:provider;"`
	ProviderId string    `gorm:"column:provider_id;size:255;not null"`
	Email      string    `gorm:"column:email;size:255"`
	CreatedAt  time.Time `gorm:"autoCreateTime,column:created_at"`
}

type UserLoginAttempt struct {
	Id        int       `gorm:"primarykey;size:16"`
	UserId    int       `gorm:"column:user_id;size:16"`
	Success   bool      `gorm:"column:success"`
	CreatedAt time.Time `gorm:"autoCreateTime;column:created_at"`
}

type UserTokens struct {
	Id        int       `gorm:"primarykey;size:16"`
	Type      int8      `gorm:"column:type;"`
	UserId    int       `gorm:"column:user_id;size:16"`
	Token     string    `gorm:"column:token;size:255"`
	Revoked   bool      `gorm:"column:revoked"`
	CreatedAt time.Time `gorm:"autoCreateTime;column:created_at"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
}

type OAuthID int

const INVALID_OAUTH_ID OAuthID = 0
const GOOGLE_OAUTH_ID OAuthID = 1
const MICROSOFT_OAUTH_ID OAuthID = 2
const APPLE_OAUTH_ID OAuthID = 3
