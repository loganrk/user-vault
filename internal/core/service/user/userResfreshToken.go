package user

import (
	"context"
	"mayilon/internal/core/domain"
	"time"
)

func (u *userService) RefreshTokenEnabled() bool {
	return u.conf.GetRefreshTokenEnabled()
}

func (u *userService) RefreshTokenRotationEnabled() bool {
	return u.conf.GetRefreshTokenRotationEnabled()
}

func (u *userService) StoreRefreshToken(ctx context.Context, userid int, token string, expiresAt time.Time) (int, error) {

	refreshTokenData := domain.UserRefreshToken{
		UserId:    userid,
		Token:     token,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}

	refreshTokenId, err := u.mysql.CreateRefreshToken(ctx, refreshTokenData)
	if err != nil {
		return 0, err
	}
	return refreshTokenId, nil
}

func (u *userService) RevokedRefreshToken(ctx context.Context, userid int, refreshToken string) error {
	err := u.mysql.RevokedRefreshToken(ctx, userid, refreshToken)

	return err
}

func (u *userService) GetRefreshTokenData(ctx context.Context, userid int, refreshToken string) (domain.UserRefreshToken, error) {
	tokenData, err := u.mysql.GetRefreshTokenData(ctx, userid, refreshToken)

	return tokenData, err

}
