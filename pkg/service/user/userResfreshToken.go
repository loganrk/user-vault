package user

import (
	"context"
	"mayilon/pkg/types"
	"time"
)

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
