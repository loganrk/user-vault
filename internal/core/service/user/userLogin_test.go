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

type mocksSetupLogin func(
	ctx context.Context,
	mockRepo *mocks.MockRepositoryMySQL,
	mockMsg *mocks.MockMessager,
	mockLogger *mocks.MockLogger,
	mockToken *mocks.MockToken,
	mockConfigUser *mocks.MockUser,
	mockUtils *mocks.MockUtils,
)

type mocksSetupOAuthLogin func(
	ctx context.Context,
	mockRepo *mocks.MockRepositoryMySQL,
	mockMsg *mocks.MockMessager,
	mockLogger *mocks.MockLogger,
	mockToken *mocks.MockToken,
	mockConfigUser *mocks.MockUser,
	mockUtils *mocks.MockUtils,
	mockOAuthProvider *mocks.MockOAuthProvider,
)

func TestLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		req domain.UserLoginClientRequest
	}

	tests := []struct {
		name       string
		args       args
		setupMocks mocksSetupLogin
		wantErr    bool
		wantMsg    string
		wantRes    domain.UserLoginClientResponse
	}{
		{
			name: "success email login",
			args: args{
				req: domain.UserLoginClientRequest{
					Email:    "alice@example.com",
					Password: "pass123",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				userData := domain.User{
					Id:                 1,
					Email:              "alice@example.com",
					UserSubscriptionId: "uuid",
					EmailVerified:      true,
					Status:             constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				mockConfigUser.EXPECT().GetMaxLoginAttempt().Return(3)
				mockConfigUser.EXPECT().GetLoginAttemptSessionPeriod().Return(3600)
				mockRepo.EXPECT().GetUserLoginFailedAttemptCount(ctx, 1, gomock.Any()).Return(0, nil)
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
				mockRepo.EXPECT().GetUserPasswordByUserID(ctx, 1).Return(domain.User{
					Id:       1,
					Password: string(hashedPassword),
				}, nil)
				mockRepo.EXPECT().CreateUserLoginAttempt(ctx, gomock.Any()).Return(1, nil)
				mockConfigUser.EXPECT().GetRefreshTokenEnabled().Return(true)
				mockConfigUser.EXPECT().GetRefreshTokenExpiry().Return(3600)
				mockToken.EXPECT().CreateRefreshToken("uuid", gomock.Any()).Return("refresh-token", nil)
				mockRepo.EXPECT().CreateToken(ctx, gomock.Any()).Return(1, nil)
			},
			wantErr: false,
			wantMsg: "",
			wantRes: domain.UserLoginClientResponse{RefreshToken: "refresh-token"},
		},
		{
			name: "user not found",
			args: args{
				req: domain.UserLoginClientRequest{
					Email: "notfound@example.com",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
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
			name: "login attempt limit reached",
			args: args{
				req: domain.UserLoginClientRequest{
					Email: "alice@example.com",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				mockConfigUser.EXPECT().GetMaxLoginAttempt().Return(3)
				mockConfigUser.EXPECT().GetLoginAttemptSessionPeriod().Return(3600)
				mockRepo.EXPECT().GetUserLoginFailedAttemptCount(ctx, 1, gomock.Any()).Return(3, nil)
			},
			wantErr: true,
			wantMsg: "Maximum login attempts reached. Please try again later.",
		},
		{
			name: "inactive account",
			args: args{
				req: domain.UserLoginClientRequest{
					Email: "alice@example.com",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				userData := domain.User{
					Id:                 1,
					Email:              "alice@example.com",
					UserSubscriptionId: "uuid",
					EmailVerified:      true,
					Status:             constant.USER_STATUS_INACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				mockConfigUser.EXPECT().GetMaxLoginAttempt().Return(3)
				mockConfigUser.EXPECT().GetLoginAttemptSessionPeriod().Return(3600)
				mockRepo.EXPECT().GetUserLoginFailedAttemptCount(ctx, 1, gomock.Any()).Return(0, nil)
			},
			wantErr: true,
			wantMsg: "account is not active",
		},
		{
			name: "unverified email",
			args: args{
				req: domain.UserLoginClientRequest{
					Email: "alice@example.com",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				userData := domain.User{
					Id:                 1,
					Email:              "alice@example.com",
					UserSubscriptionId: "uuid",
					EmailVerified:      false,
					Status:             constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				mockConfigUser.EXPECT().GetMaxLoginAttempt().Return(3)
				mockConfigUser.EXPECT().GetLoginAttemptSessionPeriod().Return(3600)
				mockRepo.EXPECT().GetUserLoginFailedAttemptCount(ctx, 1, gomock.Any()).Return(0, nil)
			},
			wantErr: true,
			wantMsg: "email is not verified",
		},
		{
			name: "invalid password",
			args: args{
				req: domain.UserLoginClientRequest{
					Email:    "alice@example.com",
					Password: "wrongpass",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				userData := domain.User{
					Id:                 1,
					Email:              "alice@example.com",
					UserSubscriptionId: "uuid",
					EmailVerified:      true,
					Status:             constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				mockConfigUser.EXPECT().GetMaxLoginAttempt().Return(3)
				mockConfigUser.EXPECT().GetLoginAttemptSessionPeriod().Return(3600)
				mockRepo.EXPECT().GetUserLoginFailedAttemptCount(ctx, 1, gomock.Any()).Return(2, nil)
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
				mockRepo.EXPECT().GetUserPasswordByUserID(ctx, 1).Return(domain.User{
					Id:       1,
					Password: string(hashedPassword),
				}, nil)
				mockRepo.EXPECT().CreateUserLoginAttempt(ctx, gomock.Any()).Return(1, nil)

			},
			wantErr: true,
			wantMsg: "Username or password is incorrect",
		},
		{
			name: "password fetch error",
			args: args{
				req: domain.UserLoginClientRequest{
					Email: "alice@example.com",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				userData := domain.User{
					Id:                 1,
					Email:              "alice@example.com",
					UserSubscriptionId: "uuid",
					EmailVerified:      true,
					Status:             constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				mockConfigUser.EXPECT().GetMaxLoginAttempt().Return(3)
				mockConfigUser.EXPECT().GetLoginAttemptSessionPeriod().Return(3600)
				mockRepo.EXPECT().GetUserLoginFailedAttemptCount(ctx, 1, gomock.Any()).Return(0, nil)
				mockRepo.EXPECT().GetUserPasswordByUserID(ctx, 1).Return(domain.User{}, assert.AnError)
				mockLogger.EXPECT().Errorw(ctx, "get_user_password_by_user_id failed",
					"userId", 1,
					"error", assert.AnError.Error(),
					"exception", constant.DBException)
			},
			wantErr: true,
			wantMsg: constant.MessageInternalServerError,
		},
		{
			name: "refresh token generation failure",
			args: args{
				req: domain.UserLoginClientRequest{
					Email:    "alice@example.com",
					Password: "pass123",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				userData := domain.User{
					Id:                 1,
					Email:              "alice@example.com",
					UserSubscriptionId: "uuid",
					EmailVerified:      true,
					Status:             constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				mockConfigUser.EXPECT().GetMaxLoginAttempt().Return(3)
				mockConfigUser.EXPECT().GetLoginAttemptSessionPeriod().Return(3600)
				mockRepo.EXPECT().GetUserLoginFailedAttemptCount(ctx, 1, gomock.Any()).Return(0, nil)
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)
				mockRepo.EXPECT().GetUserPasswordByUserID(ctx, 1).Return(domain.User{
					Id:       1,
					Password: string(hashedPassword),
				}, nil)
				mockRepo.EXPECT().CreateUserLoginAttempt(ctx, gomock.Any()).Return(1, nil)
				mockConfigUser.EXPECT().GetRefreshTokenEnabled().Return(true)
				mockConfigUser.EXPECT().GetRefreshTokenExpiry().Return(3600)
				mockToken.EXPECT().CreateRefreshToken("uuid", gomock.Any()).Return("", assert.AnError)
				mockLogger.EXPECT().Errorw(ctx, "generate_and_store_refresh_token failed",
					"userId", 1,
					"error", "failed to create refresh token. error = "+assert.AnError.Error(),
					"code", http.StatusInternalServerError,
					"exception", constant.GenericException,
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

			tt.setupMocks(ctx, mockRepo, mockMsg, mockLogger, mockToken, mockConfigUser, mockUtils)

			uc := New(mockLogger, mockToken, mockMsg, mockRepo, mockOAuthProvider, mockUtils, "myapp", mockConfigUser)

			resp, errRes := uc.Login(ctx, tt.args.req)

			if tt.wantErr {
				assert.NotZero(t, errRes.Code, "expected error code but got zero")
				assert.Equal(t, tt.wantMsg, errRes.Message)
			} else {
				assert.Zero(t, errRes.Code, "expected no error code but got one")
				assert.Equal(t, tt.wantRes.RefreshToken, resp.RefreshToken)
			}
		})
	}
}

func TestOAuthLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		req domain.UserOAuthLoginClientRequest
	}

	tests := []struct {
		name       string
		args       args
		setupMocks mocksSetupOAuthLogin
		wantErr    bool
		wantMsg    string
		wantRes    domain.UserLoginClientResponse
	}{
		{
			name: "success existing user",
			args: args{
				req: domain.UserOAuthLoginClientRequest{
					Provider: "google",
					Token:    "valid-token",
				},
			},
			setupMocks: func(ctx context.Context,
				mockRepo *mocks.MockRepositoryMySQL,
				mockMsg *mocks.MockMessager,
				mockLogger *mocks.MockLogger,
				mockToken *mocks.MockToken,
				mockConfigUser *mocks.MockUser,
				mockUtils *mocks.MockUtils,
				mockOAuthProvider *mocks.MockOAuthProvider,
			) {

				mockOAuthProvider.EXPECT().
					VerifyToken(ctx, "google", "valid-token").
					Return("alice@example.com", "Alice", domain.GOOGLE_OAUTH_ID, "pid", nil)

				user := domain.User{
					Id:                 1,
					Email:              "alice@example.com",
					Name:               "Alice",
					UserSubscriptionId: "uuid",
					Status:             constant.USER_STATUS_ACTIVE,
					EmailVerified:      true,
				}

				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(user, nil)
				mockConfigUser.EXPECT().GetMaxLoginAttempt().Return(3)
				mockConfigUser.EXPECT().GetLoginAttemptSessionPeriod().Return(3600)
				mockRepo.EXPECT().GetUserLoginFailedAttemptCount(ctx, 1, gomock.Any()).Return(0, nil)

				mockRepo.EXPECT().
					GetOauthAccountForProvider(ctx, 1, "alice@example.com", domain.GOOGLE_OAUTH_ID, "pid").
					Return(domain.OAuthAccount{}, nil)

				mockRepo.EXPECT().CreateOauthAccount(ctx, gomock.Any()).Return(1, nil)

				mockConfigUser.EXPECT().GetRefreshTokenEnabled().Return(true)
				mockConfigUser.EXPECT().GetRefreshTokenExpiry().Return(3600)
				mockToken.EXPECT().CreateRefreshToken("uuid", gomock.Any()).Return("refresh-token", nil)
				mockRepo.EXPECT().CreateToken(ctx, gomock.Any()).Return(1, nil)
			},
			wantRes: domain.UserLoginClientResponse{RefreshToken: "refresh-token"},
		},
		{
			name: "success new user created",
			args: args{
				req: domain.UserOAuthLoginClientRequest{
					Provider: "google",
					Token:    "valid-token",
				},
			},
			setupMocks: func(ctx context.Context,
				mockRepo *mocks.MockRepositoryMySQL,
				mockMsg *mocks.MockMessager,
				mockLogger *mocks.MockLogger,
				mockToken *mocks.MockToken,
				mockConfigUser *mocks.MockUser,
				mockUtils *mocks.MockUtils,
				mockOAuthProvider *mocks.MockOAuthProvider,
			) {

				mockUtils.EXPECT().GenerateUUID().Return("uuid")

				mockOAuthProvider.EXPECT().
					VerifyToken(ctx, "google", "valid-token").
					Return("bob@example.com", "Bob", domain.GOOGLE_OAUTH_ID, "pid", nil)

				mockRepo.EXPECT().GetUserByEmail(ctx, "bob@example.com").Return(domain.User{}, nil)
				mockRepo.EXPECT().CreateUser(ctx, gomock.Any()).Return(2, nil)
				mockRepo.EXPECT().CreateOauthAccount(ctx, gomock.Any()).Return(1, nil)

				user := domain.User{
					Id:                 2,
					Email:              "bob@example.com",
					UserSubscriptionId: "uuid",
					Name:               "Bob",
					Status:             constant.USER_STATUS_ACTIVE,
					EmailVerified:      true,
				}

				mockRepo.EXPECT().GetUserByUserID(ctx, 2).Return(user, nil)

				mockConfigUser.EXPECT().GetRefreshTokenEnabled().Return(true)
				mockConfigUser.EXPECT().GetRefreshTokenExpiry().Return(3600)
				mockToken.EXPECT().CreateRefreshToken("uuid", gomock.Any()).Return("refresh-token", nil)
				mockRepo.EXPECT().CreateToken(ctx, gomock.Any()).Return(1, nil)
			},
			wantRes: domain.UserLoginClientResponse{RefreshToken: "refresh-token"},
		},
		{
			name: "invalid oauth token",
			args: args{
				req: domain.UserOAuthLoginClientRequest{
					Provider: "google",
					Token:    "invalid-token",
				},
			},
			setupMocks: func(ctx context.Context,
				mockRepo *mocks.MockRepositoryMySQL,
				mockMsg *mocks.MockMessager,
				mockLogger *mocks.MockLogger,
				mockToken *mocks.MockToken,
				mockConfigUser *mocks.MockUser,
				mockUtils *mocks.MockUtils,
				mockOAuthProvider *mocks.MockOAuthProvider,
			) {

				mockOAuthProvider.EXPECT().
					VerifyToken(ctx, "google", "invalid-token").
					Return("", "", domain.INVALID_OAUTH_ID, "", assert.AnError)

				mockLogger.EXPECT().
					Error(ctx, "verify_token failed",
						"provider", "google",
						"error", assert.AnError.Error(),
						"exception", constant.AuthorizationException)
			},
			wantErr: true,
			wantMsg: "Invalid OAuth token",
		},
		{
			name: "user creation failure",
			args: args{
				req: domain.UserOAuthLoginClientRequest{
					Provider: "google",
					Token:    "valid-token",
				},
			},
			setupMocks: func(ctx context.Context,
				mockRepo *mocks.MockRepositoryMySQL,
				mockMsg *mocks.MockMessager,
				mockLogger *mocks.MockLogger,
				mockToken *mocks.MockToken,
				mockConfigUser *mocks.MockUser,
				mockUtils *mocks.MockUtils,
				mockOAuthProvider *mocks.MockOAuthProvider,
			) {

				mockUtils.EXPECT().GenerateUUID().Return("uuid")

				mockOAuthProvider.EXPECT().
					VerifyToken(ctx, "google", "valid-token").
					Return("bob@example.com", "Bob", domain.GOOGLE_OAUTH_ID, "pid", nil)

				mockRepo.EXPECT().GetUserByEmail(ctx, "bob@example.com").Return(domain.User{}, nil)
				mockRepo.EXPECT().CreateUser(ctx, gomock.Any()).Return(0, assert.AnError)

				mockLogger.EXPECT().
					Errorw(ctx, "create_user_for_o_auth failed",
						"email", "bob@example.com",
						"error", "failed to create user for OAuth. error = "+assert.AnError.Error(),
						"code", http.StatusInternalServerError,
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

			tt.setupMocks(ctx, mockRepo, mockMsg, mockLogger, mockToken, mockConfigUser, mockUtils, mockOAuthProvider)
			uc := New(mockLogger, mockToken, mockMsg, mockRepo, mockOAuthProvider, mockUtils, "myapp", mockConfigUser)

			resp, errRes := uc.OAuthLogin(ctx, tt.args.req)

			if tt.wantErr {
				assert.NotZero(t, errRes.Code, "expected error code but got zero")
				assert.Equal(t, tt.wantMsg, errRes.Message)
			} else {
				assert.Zero(t, errRes.Code, "expected no error code but got one")
				assert.Equal(t, tt.wantRes.RefreshToken, resp.RefreshToken)
			}
		})
	}
}

func TestLogout(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		req domain.UserLogoutClientRequest
	}

	tests := []struct {
		name       string
		args       args
		setupMocks mocksSetupLogin
		wantErr    bool
		wantMsg    string
		wantRes    domain.UserLogoutClientResponse
	}{
		{
			name: "success logout",
			args: args{
				req: domain.UserLogoutClientRequest{
					RefreshToken: "valid-token",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				tokenData := domain.UserTokens{
					Id:        1,
					UserId:    1,
					Token:     "valid-token",
					Type:      constant.TOKEN_TYPE_REFRESH,
					ExpiresAt: time.Now().Add(time.Hour),
					Revoked:   false,
				}
				mockRepo.EXPECT().GetUserToken(ctx, constant.TOKEN_TYPE_REFRESH, "valid-token").Return(tokenData, nil)
				mockRepo.EXPECT().RevokeToken(ctx, 1).Return(nil)
			},
			wantErr: false,
			wantMsg: "User logged out successfully",
			wantRes: domain.UserLogoutClientResponse{Message: "User logged out successfully"},
		},
		{
			name: "invalid or revoked token",
			args: args{
				req: domain.UserLogoutClientRequest{
					RefreshToken: "invalid-token",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				tokenData := domain.UserTokens{
					Id: 0,
				}

				mockRepo.EXPECT().GetUserToken(ctx, constant.TOKEN_TYPE_REFRESH, "invalid-token").Return(tokenData, nil)

			},
			wantErr: true,
			wantMsg: "Token is revoked or incorrect",
		},
		{
			name: "token fetch error",
			args: args{
				req: domain.UserLogoutClientRequest{
					RefreshToken: "valid-token",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				mockRepo.EXPECT().GetUserToken(ctx, constant.TOKEN_TYPE_REFRESH, "valid-token").Return(domain.UserTokens{}, assert.AnError)
				mockLogger.EXPECT().Errorw(ctx, "validate_refresh_token failed",
					"token", "valid-token",
					"error", "failed to fetch refresh token. error = "+assert.AnError.Error(),
					"code", http.StatusInternalServerError,
					"exception", constant.DBException,
				)
			},
			wantErr: true,
			wantMsg: constant.MessageInternalServerError,
		},
		{
			name: "token revocation error",
			args: args{
				req: domain.UserLogoutClientRequest{
					RefreshToken: "valid-token",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				tokenData := domain.UserTokens{
					Id:        1,
					UserId:    1,
					Token:     "valid-token",
					Type:      constant.TOKEN_TYPE_REFRESH,
					ExpiresAt: time.Now().Add(time.Hour),
					Revoked:   false,
				}
				mockRepo.EXPECT().GetUserToken(ctx, constant.TOKEN_TYPE_REFRESH, "valid-token").Return(tokenData, nil)
				mockRepo.EXPECT().RevokeToken(ctx, 1).Return(assert.AnError)
				mockLogger.EXPECT().Errorw(ctx, "revoke_refresh_token failed",
					"tokenId", 1,
					"error", assert.AnError.Error(),
					"code", http.StatusInternalServerError,
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

			tt.setupMocks(ctx, mockRepo, mockMsg, mockLogger, mockToken, mockConfigUser, mockUtils)

			uc := New(mockLogger, mockToken, mockMsg, mockRepo, mockOAuthProvider, mockUtils, "myapp", mockConfigUser)

			resp, errRes := uc.Logout(ctx, tt.args.req)

			if tt.wantErr {
				assert.NotZero(t, errRes.Code, "expected error code but got zero")
				assert.Equal(t, tt.wantMsg, errRes.Message)
			} else {
				assert.Zero(t, errRes.Code, "expected no error code but got one")
				assert.Equal(t, tt.wantRes.Message, resp.Message)
			}
		})
	}
}
