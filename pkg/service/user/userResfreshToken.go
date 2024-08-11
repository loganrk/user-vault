package user

import (
	"context"
	"mayilon/pkg/types"
	"time"
)

func (u *userService) RefreshTokenEnabled() bool {
	return u.conf.GetRefreshTokenEnabled()
}

func (u *userService) RefreshTokenRotationEnabled() bool {
	return u.conf.GetRefreshTokenRotationEnabled()
}

func (u *userService) StoreRefreshToken(ctx context.Context, userid int, token string, expiresAt time.Time) (int, error) {

	refreshTokenData := types.UserRefreshToken{
		UserId:    userid,
		Token:     token,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}

	refreshTokenId, err := u.store.CreateRefreshToken(ctx, refreshTokenData)
	if err != nil {
		return 0, err
	}
	return refreshTokenId, nil
}

func (u *userService) RevokedRefreshToken(ctx context.Context, userid int, refreshToken string) error {
	err := u.store.RevokedRefreshToken(ctx, userid, refreshToken)

	return err
}

func (u *userService) GetRefreshTokenData(ctx context.Context, userid int, refreshToken string) (types.UserRefreshToken, error) {
	tokenData, err := u.store.GetRefreshTokenData(ctx, userid, refreshToken)

	return tokenData, err

}
