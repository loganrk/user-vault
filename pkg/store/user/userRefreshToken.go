package user

import (
	"context"
	"mayilon/pkg/types"
)

func (s *userStore) CreateRefreshToken(ctx context.Context, refreshTokenData types.UserRefreshToken) (int, error) {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userRefreshToken).Create(&refreshTokenData)
	return refreshTokenData.Id, result.Error
}

func (s *userStore) RevokedRefreshToken(ctx context.Context, userid int, refreshToken string) error {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userRefreshToken).Where("user_id = ? and token = ?", userid, refreshToken).Update("revoked", true)
	return result.Error

}
