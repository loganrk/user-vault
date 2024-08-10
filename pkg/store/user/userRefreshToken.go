package user

import (
	"context"
	"mayilon/pkg/types"

	"gorm.io/gorm"
)

func (s *userStore) CreateRefreshToken(ctx context.Context, refreshTokenData types.UserRefreshToken) (int, error) {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.GetUserRefreshToken()).Create(&refreshTokenData)
	return refreshTokenData.Id, result.Error
}

func (s *userStore) RevokedRefreshToken(ctx context.Context, userid int, refreshToken string) error {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.GetUserRefreshToken()).Where("user_id = ? and token = ?", userid, refreshToken).Update("revoked", true)
	return result.Error

}

func (s *userStore) GetRefreshTokenData(ctx context.Context, userid int, refreshToken string) (types.UserRefreshToken, error) {
	var tokenData types.UserRefreshToken
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.GetUserRefreshToken()).Select("id", "expires_at", "revoked").Where("user_id = ? and token = ?", userid, refreshToken).First(&tokenData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}

	return tokenData, result.Error
}
