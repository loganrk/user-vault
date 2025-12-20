package user

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"

	"github.com/loganrk/user-vault/internal/constant"
	"github.com/loganrk/user-vault/internal/core/domain"
	"github.com/loganrk/user-vault/test/mocks"
)

type mocksSetupPassword func(
	ctx context.Context,
	mockRepo *mocks.MockRepositoryMySQL,
	mockMsg *mocks.MockMessager,
	mockLogger *mocks.MockLogger,
	mockConfigUser *mocks.MockUser,
	mockUtils *mocks.MockUtils,
)

func TestForgotPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		req domain.UserForgotPasswordClientRequest
	}

	tests := []struct {
		name       string
		args       args
		setupMocks mocksSetupPassword
		wantErr    bool
		wantMsg    string
		wantRes    domain.UserForgotPasswordClientResponse
	}{
		{
			name: "success email reset",
			args: args{
				req: domain.UserForgotPasswordClientRequest{
					Email: "alice@example.com",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					Name:          "Alice",
					EmailVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				mockRepo.EXPECT().RevokeAllTokens(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL, 1).Return(nil)
				mockConfigUser.EXPECT().GetPasswordResetTokenExpiry().Return(1200)
				mockRepo.EXPECT().CreateToken(ctx, gomock.Any()).Return(1, nil)
				mockConfigUser.EXPECT().GetPasswordResetLink().Return("http://example.com/reset?token={{token}}")
				mockUtils.EXPECT().GenerateString(25).Return("mock-token")
				mockMsg.EXPECT().PublishPasswordResetEmail("alice@example.com", constant.USER_PASSWORD_RESET_EMAIL_SUBJECT, "Alice", "http://example.com/reset?token=mock-token").Return(nil)
				mockLogger.EXPECT().Infow(ctx, "password reset request sent successfully", "event", "user_forgot_password_success", "userId", 1)
			},
			wantErr: false,
			wantMsg: "Password reset request sent successfully",
			wantRes: domain.UserForgotPasswordClientResponse{Message: "Password reset request sent successfully"},
		},
		{
			name: "success phone reset",
			args: args{
				req: domain.UserForgotPasswordClientRequest{
					Phone: "+1234567890",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Phone:         "+1234567890",
					Name:          "Alice",
					PhoneVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByPhone(ctx, "+1234567890").Return(userData, nil)
				mockRepo.EXPECT().RevokeAllTokens(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_PHONE, 1).Return(nil)
				mockConfigUser.EXPECT().GetPasswordResetTokenExpiry().Return(1200)
				mockRepo.EXPECT().CreateToken(ctx, gomock.Any()).Return(1, nil)
				mockUtils.EXPECT().GenerateOTPString(6).Return("123456")
				mockMsg.EXPECT().PublishPasswordResetPhone("+1234567890", "Alice", "123456").Return(nil)
				mockLogger.EXPECT().Infow(ctx, "password reset request sent successfully", "event", "user_forgot_password_success", "userId", 1)
			},
			wantErr: false,
			wantMsg: "Password reset request sent successfully",
			wantRes: domain.UserForgotPasswordClientResponse{Message: "Password reset request sent successfully"},
		},
		{
			name: "user not found",
			args: args{
				req: domain.UserForgotPasswordClientRequest{
					Email: "notfound@example.com",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmail(ctx, "notfound@example.com").Return(domain.User{}, nil)
				mockLogger.EXPECT().Errorw(ctx, "fetch_user failed",
					"email", "notfound@example.com",
					"phone", "",
					"error", "user not found for user email",
					"code", http.StatusNotFound,
					"exception", constant.ResourceNotFoundException)
			},
			wantErr: true,
			wantMsg: constant.MessageInvalidApiParameters,
		},
		{
			name: "unverified email",
			args: args{
				req: domain.UserForgotPasswordClientRequest{
					Email: "alice@example.com",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: false,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
			},
			wantErr: true,
			wantMsg: "email is not verified",
		},
		{
			name: "inactive account",
			args: args{
				req: domain.UserForgotPasswordClientRequest{
					Email: "alice@example.com",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_INACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)

			},
			wantErr: true,
			wantMsg: "account is not active",
		},
		{
			name: "token generation failure",
			args: args{
				req: domain.UserForgotPasswordClientRequest{
					Email: "alice@example.com",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				mockRepo.EXPECT().RevokeAllTokens(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL, 1).Return(assert.AnError)
				mockLogger.EXPECT().Errorw(ctx, "generate_password_reset_token failed",
					"userId", 1,
					"error", "failed to revoke old tokens. error = "+assert.AnError.Error(),
					"code", http.StatusInternalServerError,
					"exception", constant.DBException)

			},
			wantErr: true,
			wantMsg: constant.MessageInternalServerError,
		},
		{
			name: "email sending failure",
			args: args{
				req: domain.UserForgotPasswordClientRequest{
					Email: "alice@example.com",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					Name:          "Alice",
					EmailVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				mockRepo.EXPECT().RevokeAllTokens(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL, 1).Return(nil)
				mockConfigUser.EXPECT().GetPasswordResetTokenExpiry().Return(1200)
				mockRepo.EXPECT().CreateToken(ctx, gomock.Any()).Return(1, nil)
				mockConfigUser.EXPECT().GetPasswordResetLink().Return("http://example.com/reset?token={{token}}")
				mockUtils.EXPECT().GenerateString(25).Return("mock-token")
				mockMsg.EXPECT().PublishPasswordResetEmail("alice@example.com", constant.USER_PASSWORD_RESET_EMAIL_SUBJECT, "Alice", "http://example.com/reset?token=mock-token").Return(assert.AnError)
				mockLogger.EXPECT().Errorw(ctx, "failed to send verification email",
					"userId", 1,
					"error", assert.AnError.Error(),
					"code", http.StatusInternalServerError,
					"exception", constant.NetworkException,
				)
			},
			wantErr: true,
			wantMsg: constant.MessageInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()

			mockRepo := mocks.NewMockRepositoryMySQL(ctrl)
			mockToken := mocks.NewMockToken(ctrl)
			mockMsg := mocks.NewMockMessager(ctrl)
			mockLogger := mocks.NewMockLogger(ctrl)
			mockConfigUser := mocks.NewMockUser(ctrl)
			mockUtils := mocks.NewMockUtils(ctrl)
			mockOAuthProvider := mocks.NewMockOAuthProvider(ctrl)

			tt.setupMocks(ctx, mockRepo, mockMsg, mockLogger, mockConfigUser, mockUtils)

			uc := New(mockLogger, mockToken, mockMsg, mockRepo, mockOAuthProvider, mockUtils, "myapp", mockConfigUser)

			resp, errRes := uc.ForgotPassword(ctx, tt.args.req)

			if tt.wantErr {
				assert.NotZero(t, errRes.Code, "expected error code but got zero")
				assert.Equal(t, tt.wantMsg, errRes.Message)
			} else {
				assert.Zero(t, errRes.Code, "expected no error code but got one")
				assert.Equal(t, tt.wantMsg, resp.Message)
			}
		})
	}
}

func TestResetPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		req domain.UserResetPasswordClientRequest
	}

	tests := []struct {
		name       string
		args       args
		setupMocks mocksSetupPassword
		wantErr    bool
		wantMsg    string
		wantRes    domain.UserResetPasswordClientResponse
	}{
		{
			name: "success email reset",
			args: args{
				req: domain.UserResetPasswordClientRequest{
					Email:    "alice@example.com",
					Token:    "valid-token",
					Password: "newpass123",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				tokenData := domain.UserTokens{
					Id:        1,
					UserId:    1,
					Token:     "valid-token",
					Type:      constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL,
					ExpiresAt: time.Now().Add(time.Hour),
					Revoked:   false,
				}
				mockRepo.EXPECT().GetUserLastTokenByUserId(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL, 1).Return(tokenData, nil)
				mockConfigUser.EXPECT().GetPasswordHashCost().Return(bcrypt.DefaultCost)
				mockRepo.EXPECT().UpdatePassword(ctx, 1, gomock.Any()).Return(nil)
				mockRepo.EXPECT().RevokeToken(ctx, 1).Return(nil)
			},
			wantErr: false,
			wantMsg: "Password has been reset successfully",
			wantRes: domain.UserResetPasswordClientResponse{Message: "Password has been reset successfully"},
		},
		{
			name: "success phone reset",
			args: args{
				req: domain.UserResetPasswordClientRequest{
					Phone:    "+1234567890",
					Token:    "valid-token",
					Password: "newpass123",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Phone:         "+1234567890",
					PhoneVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByPhone(ctx, "+1234567890").Return(userData, nil)
				tokenData := domain.UserTokens{
					Id:        1,
					UserId:    1,
					Token:     "valid-token",
					Type:      constant.TOKEN_TYPE_PASSWORD_RESET_PHONE,
					ExpiresAt: time.Now().Add(time.Hour),
					Revoked:   false,
				}
				mockRepo.EXPECT().GetUserLastTokenByUserId(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_PHONE, 1).Return(tokenData, nil)
				mockConfigUser.EXPECT().GetPasswordHashCost().Return(bcrypt.DefaultCost)
				mockRepo.EXPECT().UpdatePassword(ctx, 1, gomock.Any()).Return(nil)

				mockRepo.EXPECT().RevokeToken(ctx, 1).Return(nil)
			},
			wantErr: false,
			wantMsg: "Password has been reset successfully",
			wantRes: domain.UserResetPasswordClientResponse{Message: "Password has been reset successfully"},
		},
		{
			name: "user not found",
			args: args{
				req: domain.UserResetPasswordClientRequest{
					Email: "notfound@example.com",
					Token: "valid-token",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmail(ctx, "notfound@example.com").Return(domain.User{}, nil)
				mockLogger.EXPECT().Errorw(ctx, "fetch_user failed",
					"email", "notfound@example.com",
					"phone", "",
					"error", "user not found for user email",
					"code", http.StatusNotFound,
					"exception", constant.ResourceNotFoundException)
			},
			wantErr: true,
			wantMsg: constant.MessageInvalidApiParameters,
		},
		{
			name: "unverified email",
			args: args{
				req: domain.UserResetPasswordClientRequest{
					Email: "alice@example.com",
					Token: "valid-token",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: false,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
			},
			wantErr: true,
			wantMsg: "email is not verified",
		},
		{
			name: "inactive account",
			args: args{
				req: domain.UserResetPasswordClientRequest{
					Email: "alice@example.com",
					Token: "valid-token",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_INACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
			},
			wantErr: true,
			wantMsg: "account is not active",
		},
		{
			name: "invalid token",
			args: args{
				req: domain.UserResetPasswordClientRequest{
					Email: "alice@example.com",
					Token: "invalid-token",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				tokenData := domain.UserTokens{
					Id:        1,
					UserId:    1,
					Token:     "valid-token",
					Type:      constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL,
					ExpiresAt: time.Now().Add(time.Hour),
					Revoked:   false,
				}
				mockRepo.EXPECT().GetUserLastTokenByUserId(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL, 1).Return(tokenData, nil)
			},
			wantErr: true,
			wantMsg: "invalid token",
		},
		{
			name: "expired token",
			args: args{
				req: domain.UserResetPasswordClientRequest{
					Email: "alice@example.com",
					Token: "valid-token",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				tokenData := domain.UserTokens{
					Id:        1,
					UserId:    1,
					Token:     "valid-token",
					Type:      constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL,
					ExpiresAt: time.Now().Add(-time.Hour),
					Revoked:   false,
				}
				mockRepo.EXPECT().GetUserLastTokenByUserId(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL, 1).Return(tokenData, nil)
			},
			wantErr: true,
			wantMsg: "token already expired",
		},
		{
			name: "password update error",
			args: args{
				req: domain.UserResetPasswordClientRequest{
					Email:    "alice@example.com",
					Token:    "valid-token",
					Password: "newpass123",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				tokenData := domain.UserTokens{
					Id:        1,
					UserId:    1,
					Token:     "valid-token",
					Type:      constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL,
					ExpiresAt: time.Now().Add(time.Hour),
					Revoked:   false,
				}
				mockRepo.EXPECT().GetUserLastTokenByUserId(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL, 1).Return(tokenData, nil)
				mockConfigUser.EXPECT().GetPasswordHashCost().Return(bcrypt.DefaultCost)
				mockRepo.EXPECT().UpdatePassword(ctx, 1, gomock.Any()).Return(assert.AnError)
				mockLogger.EXPECT().Errorw(ctx, "update_user_password failed",
					"userId", 1,
					"error", "failed to update the user password. error = "+assert.AnError.Error(),
					"exception", constant.DBException)
			},
			wantErr: true,
			wantMsg: constant.MessageInternalServerError,
		},
		{
			name: "token revocation error",
			args: args{
				req: domain.UserResetPasswordClientRequest{
					Email:    "alice@example.com",
					Token:    "valid-token",
					Password: "newpass123",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				tokenData := domain.UserTokens{
					Id:        1,
					UserId:    1,
					Token:     "valid-token",
					Type:      constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL,
					ExpiresAt: time.Now().Add(time.Hour),
					Revoked:   false,
				}
				mockRepo.EXPECT().GetUserLastTokenByUserId(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL, 1).Return(tokenData, nil)
				mockConfigUser.EXPECT().GetPasswordHashCost().Return(bcrypt.DefaultCost)
				mockRepo.EXPECT().UpdatePassword(ctx, 1, gomock.Any()).Return(nil)
				mockRepo.EXPECT().RevokeToken(ctx, 1).Return(assert.AnError)

				mockLogger.EXPECT().Errorw(ctx, "revoke_token failed",
					"tokenId", 1,
					"error", assert.AnError.Error(),
					"exception", constant.DBException)
			},
			wantErr: true,
			wantMsg: constant.MessageInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()

			mockRepo := mocks.NewMockRepositoryMySQL(ctrl)
			mockToken := mocks.NewMockToken(ctrl)
			mockMsg := mocks.NewMockMessager(ctrl)
			mockLogger := mocks.NewMockLogger(ctrl)
			mockConfigUser := mocks.NewMockUser(ctrl)
			mockUtils := mocks.NewMockUtils(ctrl)
			mockOAuthProvider := mocks.NewMockOAuthProvider(ctrl)

			tt.setupMocks(ctx, mockRepo, mockMsg, mockLogger, mockConfigUser, mockUtils)

			uc := New(mockLogger, mockToken, mockMsg, mockRepo, mockOAuthProvider, mockUtils, "myapp", mockConfigUser)

			resp, errRes := uc.ResetPassword(ctx, tt.args.req)

			if tt.wantErr {
				assert.NotZero(t, errRes.Code, "expected error code but got zero")
				assert.Equal(t, tt.wantMsg, errRes.Message)
			} else {
				assert.Zero(t, errRes.Code, "expected no error code but got one")
				assert.Equal(t, tt.wantMsg, resp.Message)
			}
		})
	}
}
