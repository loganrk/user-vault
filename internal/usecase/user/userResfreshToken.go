package user

import (
	"context"
	"mayilon/internal/domain"
	"time"
)

func (u *userusecase) RefreshTokenEnabled() bool {
	return u.conf.GetRefreshTokenEnabled()
}

func (u *userusecase) RefreshTokenRotationEnabled() bool {
	return u.conf.GetRefreshTokenRotationEnabled()
}

func (u *userusecase) GetRefreshTokenExpiry() time.Time {
	return time.Now().Add(time.Second * time.Duration(u.conf.GetRefreshTokenExpiry()))
}

func (u *userusecase) GetAccessTokenExpiry() time.Time {
	return time.Now().Add(time.Second * time.Duration(u.conf.GetAccessTokenExpiry()))
}

func (u *userusecase) StoreRefreshToken(ctx context.Context, userid int, token string, expiresAt time.Time) (int, error) {

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

func (u *userusecase) RevokedRefreshToken(ctx context.Context, userid int, refreshToken string) error {
	err := u.mysql.RevokedRefreshToken(ctx, userid, refreshToken)

	return err
}

func (u *userusecase) GetRefreshTokenData(ctx context.Context, userid int, refreshToken string) (domain.UserRefreshToken, error) {
	tokenData, err := u.mysql.GetRefreshTokenData(ctx, userid, refreshToken)

	return tokenData, err

}
