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

func (u *userService) StoreRefreshToken(ctx context.Context, userid int, token string, expiresAt time.Time) int {

	refreshTokenData := types.UserRefreshToken{
		UserId:    userid,
		Token:     token,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}

	refreshTokenId, err := u.store.CreateRefreshToken(ctx, refreshTokenData)
	if err != nil {
		return 0
	}
	return refreshTokenId
}

func (u *userService) RevokedRefreshToken(ctx context.Context, userid int, refreshToken string) bool {
	err := u.store.RevokedRefreshToken(ctx, userid, refreshToken)
	if err != nil {
		return false
	}

	return true
}

func (u *userService) GetRefreshTokenData(ctx context.Context, userid int, refreshToken string) types.UserRefreshToken {
	tokenData, err := u.store.GetRefreshTokenData(ctx, userid, refreshToken)
	if err != nil {
		return types.UserRefreshToken{}
	}

	return tokenData

}
