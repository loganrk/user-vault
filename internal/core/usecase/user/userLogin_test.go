package user

import (
	"context"
	"net/http"
	"testing"

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
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser) {
				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				mockConfigUser.EXPECT().GetMaxLoginAttempt().Return(3)
				mockConfigUser.EXPECT().GetLoginAttemptSessionPeriod().Return(3600)
				mockRepo.EXPECT().GetUserLoginFailedAttemptCount(ctx, 1, gomock.Any()).Return(0, nil)
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("pass123"+constant.TEST_SALT), bcrypt.DefaultCost)
				mockRepo.EXPECT().GetUserPasswordByUserID(ctx, 1).Return(domain.User{
					Id:       1,
					Password: string(hashedPassword),
					Salt:     constant.TEST_SALT,
				}, nil)
				mockRepo.EXPECT().CreateUserLoginAttempt(ctx, gomock.Any()).Return(1, nil)
				mockConfigUser.EXPECT().GetRefreshTokenEnabled().Return(true)
				mockConfigUser.EXPECT().GetRefreshTokenExpiry().Return(3600)
				mockToken.EXPECT().CreateRefreshToken(1, gomock.Any()).Return("refresh-token", nil)
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
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser) {
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
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser) {
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
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser) {
				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_INACTIVE,
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
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser) {
				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: false,
					Status:        constant.USER_STATUS_ACTIVE,
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
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser) {
				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				mockConfigUser.EXPECT().GetMaxLoginAttempt().Return(3)
				mockConfigUser.EXPECT().GetLoginAttemptSessionPeriod().Return(3600)
				mockRepo.EXPECT().GetUserLoginFailedAttemptCount(ctx, 1, gomock.Any()).Return(2, nil)
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("pass123"+constant.TEST_SALT), bcrypt.DefaultCost)
				mockRepo.EXPECT().GetUserPasswordByUserID(ctx, 1).Return(domain.User{
					Id:       1,
					Password: string(hashedPassword),
					Salt:     constant.TEST_SALT,
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
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser) {
				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
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
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockToken *mocks.MockToken, mockConfigUser *mocks.MockUser) {
				userData := domain.User{
					Id:            1,
					Email:         "alice@example.com",
					EmailVerified: true,
					Status:        constant.USER_STATUS_ACTIVE,
				}
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(userData, nil)
				mockConfigUser.EXPECT().GetMaxLoginAttempt().Return(3)
				mockConfigUser.EXPECT().GetLoginAttemptSessionPeriod().Return(3600)
				mockRepo.EXPECT().GetUserLoginFailedAttemptCount(ctx, 1, gomock.Any()).Return(0, nil)
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("pass123"+constant.TEST_SALT), bcrypt.DefaultCost)
				mockRepo.EXPECT().GetUserPasswordByUserID(ctx, 1).Return(domain.User{
					Id:       1,
					Password: string(hashedPassword),
					Salt:     constant.TEST_SALT,
				}, nil)
				mockRepo.EXPECT().CreateUserLoginAttempt(ctx, gomock.Any()).Return(1, nil)
				mockConfigUser.EXPECT().GetRefreshTokenEnabled().Return(true)
				mockConfigUser.EXPECT().GetRefreshTokenExpiry().Return(3600)
				mockToken.EXPECT().CreateRefreshToken(1, gomock.Any()).Return("", assert.AnError)
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

			uc := New(mockLogger, mockToken, mockMsg, mockRepo, "myapp", mockConfigUser)

			tt.setupMocks(ctx, mockRepo, mockMsg, mockLogger, mockToken, mockConfigUser)

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
