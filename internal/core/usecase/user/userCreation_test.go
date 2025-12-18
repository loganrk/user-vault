package user

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/loganrk/user-vault/internal/core/domain"
	"github.com/loganrk/user-vault/internal/shared/constant"
	"github.com/loganrk/user-vault/test/mocks"
)

type mocksSetup func(
	ctx context.Context,
	mockRepo *mocks.MockRepositoryMySQL,
	mockMsg *mocks.MockMessager,
	mockLogger *mocks.MockLogger,
	mockConfigUser *mocks.MockUser,
	mockUtils *mocks.MockUtils,

)

func TestRegister(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		req domain.UserRegisterClientRequest
	}

	tests := []struct {
		name       string
		args       args
		setupMocks mocksSetup
		wantErr    bool
		wantMsg    string
	}{
		{
			name: "success email registration",
			args: args{
				req: domain.UserRegisterClientRequest{
					Name:     "Alice",
					Email:    "alice@example.com",
					Password: "pass123",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmailOrPhone(ctx, "alice@example.com", "").Return(domain.User{}, nil)
				mockConfigUser.EXPECT().GetPasswordHashCost().Return(12)
				mockRepo.EXPECT().CreateUser(ctx, gomock.Any()).Return(1, nil)
				mockRepo.EXPECT().GetUserByUserID(ctx, 1).Return(domain.User{Id: 1, Name: "Alice", Email: "alice@example.com"}, nil)
				mockRepo.EXPECT().RevokeAllTokens(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, 1).Return(nil)
				mockConfigUser.EXPECT().GetVerificationTokenExpiry().Return(1200)
				mockRepo.EXPECT().CreateToken(ctx, gomock.Any()).Return(1, nil)
				mockConfigUser.EXPECT().GetVerificationLink().Return("http://example.com/verify?token={{token}}")
				mockUtils.EXPECT().GenerateString(25).Return("mock-token")
				mockMsg.EXPECT().PublishVerificationEmail("alice@example.com", constant.USER_ACTIVATION_EMAIL_SUBJECT, "Alice", "http://example.com/verify?token=mock-token").Return(nil)

			},
			wantErr: false,
			wantMsg: "Account created successfully.",
		},
		{
			name: "user already exists",
			args: args{
				req: domain.UserRegisterClientRequest{
					Email: "existing@example.com",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmailOrPhone(ctx, "existing@example.com", "").Return(domain.User{Id: 10}, nil)
				mockLogger.EXPECT().Warnw(ctx, "User already exists", "event", "register_failed", "email", "existing@example.com", "phone", "")
			},
			wantErr: true,
			wantMsg: "User already exists",
		},
		{
			name: "create user failure",
			args: args{
				req: domain.UserRegisterClientRequest{
					Name:     "Bob",
					Email:    "bob@example.com",
					Password: "pass123",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmailOrPhone(ctx, "bob@example.com", "").Return(domain.User{}, nil)
				mockConfigUser.EXPECT().GetPasswordHashCost().Return(12)
				mockRepo.EXPECT().CreateUser(ctx, gomock.Any()).Return(0, assert.AnError)
				mockLogger.EXPECT().Errorw(ctx, "create_user failed", "email", "bob@example.com", "phone", "", "error", "failed to create user. error = "+assert.AnError.Error(), "code", http.StatusInternalServerError, "exception", constant.DBException)
			},
			wantErr: true,
			wantMsg: constant.MessageInternalServerError,
		},
		{
			name: "fetch user failure",
			args: args{
				req: domain.UserRegisterClientRequest{
					Name:     "Eve",
					Email:    "eve@example.com",
					Password: "pass123",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmailOrPhone(ctx, "eve@example.com", "").Return(domain.User{}, nil)
				mockConfigUser.EXPECT().GetPasswordHashCost().Return(12)
				mockRepo.EXPECT().CreateUser(ctx, gomock.Any()).Return(2, nil)
				mockRepo.EXPECT().GetUserByUserID(ctx, 2).Return(domain.User{}, assert.AnError)
				mockLogger.EXPECT().Errorw(ctx, "fetch_user_by_id failed", "userId", 2, "error", "failed to retrieve user by user id. error = "+assert.AnError.Error(), "code", http.StatusInternalServerError, "exception", constant.DBException)
			},
			wantErr: true,
			wantMsg: constant.MessageInternalServerError,
		},
		{
			name: "token generation failure",
			args: args{
				req: domain.UserRegisterClientRequest{
					Name:     "Carl",
					Email:    "carl@example.com",
					Password: "pass123",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmailOrPhone(ctx, "carl@example.com", "").Return(domain.User{}, nil)
				mockConfigUser.EXPECT().GetPasswordHashCost().Return(12)
				mockRepo.EXPECT().CreateUser(ctx, gomock.Any()).Return(3, nil)
				mockRepo.EXPECT().GetUserByUserID(ctx, 3).Return(domain.User{Id: 3, Name: "Carl", Email: "carl@example.com"}, nil)
				mockRepo.EXPECT().RevokeAllTokens(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, 3).Return(assert.AnError)
				mockLogger.EXPECT().Errorw(ctx, "generate_verification_token failed", "userId", 3, "tokenType", constant.TOKEN_TYPE_ACTIVATION_EMAIL, "error", "failed to revoke existing tokens. error = "+assert.AnError.Error(), "code", http.StatusInternalServerError, "exception", constant.DBException)
			},
			wantErr: true,
			wantMsg: constant.MessageInternalServerError,
		},
		{
			name: "publish verification email failure",
			args: args{
				req: domain.UserRegisterClientRequest{
					Name:     "Maya",
					Email:    "maya@example.com",
					Password: "pass123",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmailOrPhone(ctx, "maya@example.com", "").Return(domain.User{}, nil)
				mockConfigUser.EXPECT().GetPasswordHashCost().Return(12)
				mockRepo.EXPECT().CreateUser(ctx, gomock.Any()).Return(4, nil)
				mockRepo.EXPECT().GetUserByUserID(ctx, 4).Return(domain.User{Id: 4, Name: "Maya", Email: "maya@example.com"}, nil)
				mockRepo.EXPECT().RevokeAllTokens(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, 4).Return(nil)
				mockConfigUser.EXPECT().GetVerificationTokenExpiry().Return(1200)
				mockRepo.EXPECT().CreateToken(ctx, gomock.Any()).Return(1, nil)
				mockConfigUser.EXPECT().GetVerificationLink().Return("http://example.com/verify?token={{token}}")
				mockUtils.EXPECT().GenerateString(25).Return("mock-token")
				mockMsg.EXPECT().PublishVerificationEmail("maya@example.com", constant.USER_ACTIVATION_EMAIL_SUBJECT, "Maya", "http://example.com/verify?token=mock-token").Return(assert.AnError)
				mockLogger.EXPECT().Errorw(ctx, "publish_verification_email failed", "userId", 4, "error", assert.AnError.Error(), "code", http.StatusInternalServerError, "exception", constant.NetworkException)
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

			resp, errRes := uc.Register(ctx, tt.args.req)

			if tt.wantErr {
				assert.NotZero(t, errRes.Code, "expected error code but got zero", "name", tt.name)
				assert.Equal(t, tt.wantMsg, errRes.Message, "name", tt.name)
			} else {
				assert.Zero(t, errRes.Code, "expected no error code but got one", "name", tt.name)
				assert.Equal(t, tt.wantMsg, resp.Message, "name", tt.name)
			}
		})
	}
}

func TestVerifyUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		req domain.UserVerifyClientRequest
	}

	tests := []struct {
		name       string
		args       args
		setupMocks mocksSetup
		wantErr    bool
		wantMsg    string
	}{
		{
			name: "success email verification",
			args: args{req: domain.UserVerifyClientRequest{Email: "alice@example.com", Token: "valid-token"}},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmail(ctx, "alice@example.com").Return(domain.User{Id: 1, Email: "alice@example.com", EmailVerified: false}, nil)
				mockRepo.EXPECT().GetUserLastTokenByUserId(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, 1).Return(domain.UserTokens{Id: 1, Token: "valid-token", Revoked: false, ExpiresAt: time.Now().Add(1 * time.Hour)}, nil)
				mockRepo.EXPECT().UpdateEmailVerfied(ctx, 1).Return(nil)
				mockRepo.EXPECT().RevokeToken(ctx, 1).Return(nil)
			},
			wantErr: false,
			wantMsg: "User account activated successfully.",
		},
		{
			name: "user not found",
			args: args{req: domain.UserVerifyClientRequest{Email: "notfound@example.com", Token: "abc"}},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmail(ctx, "notfound@example.com").Return(domain.User{}, nil)
				mockLogger.EXPECT().Errorw(ctx, "fetch_user failed", "email", "notfound@example.com", "phone", "", "error", "user not found for user email", "code", http.StatusNotFound, "exception", constant.ResourceNotFoundException)
			},
			wantErr: true,
			wantMsg: constant.MessageInvalidApiParameters,
		},
		{
			name: "email already verified",
			args: args{req: domain.UserVerifyClientRequest{Email: "bob@example.com", Token: "abc"}},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmail(ctx, "bob@example.com").Return(domain.User{Id: 2, Email: "bob@example.com", EmailVerified: true}, nil)
			},
			wantErr: true,
			wantMsg: "Your email is already verified",
		},
		{
			name: "token expired",
			args: args{req: domain.UserVerifyClientRequest{Email: "exp@example.com", Token: "expired"}},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				mockRepo.EXPECT().GetUserByEmail(ctx, "exp@example.com").Return(domain.User{Id: 3, Email: "exp@example.com", EmailVerified: false}, nil)

				mockRepo.EXPECT().GetUserLastTokenByUserId(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, 3).Return(domain.UserTokens{Token: "expired", Revoked: false, ExpiresAt: time.Now().Add(-1 * time.Hour)}, nil)

				// mockLogger.EXPECT().Errorw(ctx, "validate_user_token failed", "userId", 3, "tokenType", constant.TOKEN_TYPE_ACTIVATION_EMAIL, "token", "expired", "error", "token already expired", "code", http.StatusBadRequest, "exception", constant.ValidationException)

			},
			wantErr: true,
			wantMsg: "token already expired",
		},
		{
			name: "invalid token value",
			args: args{req: domain.UserVerifyClientRequest{Email: "charlie@example.com", Token: "wrong-token"}},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {

				mockRepo.EXPECT().GetUserByEmail(ctx, "charlie@example.com").Return(domain.User{Id: 4, Email: "charlie@example.com", EmailVerified: false}, nil)

				mockRepo.EXPECT().GetUserLastTokenByUserId(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, 4).Return(domain.UserTokens{Token: "correct-token", Revoked: false, ExpiresAt: time.Now().Add(1 * time.Hour)}, nil)

				// mockLogger.EXPECT().Errorw(ctx, "validate_user_token failed", "userId", 4, "tokenType", constant.TOKEN_TYPE_ACTIVATION_EMAIL, "token", "wrong-token", "error", "invalid token", "code", http.StatusBadRequest, "exception", constant.ValidationException)
			},
			wantErr: true,
			wantMsg: "invalid token",
		},
		{
			name: "update email failed",
			args: args{req: domain.UserVerifyClientRequest{Email: "err@example.com", Token: "valid-token"}},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfigUser *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmail(ctx, "err@example.com").Return(domain.User{Id: 5, Email: "err@example.com", EmailVerified: false}, nil)
				mockRepo.EXPECT().GetUserLastTokenByUserId(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, 5).Return(domain.UserTokens{Id: 5, Token: "valid-token", Revoked: false, ExpiresAt: time.Now().Add(1 * time.Hour)}, nil)
				mockRepo.EXPECT().UpdateEmailVerfied(ctx, 5).Return(assert.AnError)
				mockLogger.EXPECT().Errorw(ctx, "update_email_verfied failed", "userId", 5, "error", assert.AnError.Error(), "code", http.StatusInternalServerError, "exception", constant.DBException)
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

			resp, errRes := uc.VerifyUser(ctx, tt.args.req)

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

func TestResendVerification(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		req domain.UserResendVerificationClientRequest
	}

	tests := []struct {
		name       string
		args       args
		setupMocks mocksSetup
		wantErr    bool
		wantMsg    string
	}{
		{
			name: "email resend success",
			args: args{req: domain.UserResendVerificationClientRequest{Email: "john@example.com"}},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfig *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmail(ctx, "john@example.com").Return(domain.User{Id: 1, Email: "john@example.com", Name: "John", EmailVerified: false}, nil)
				mockRepo.EXPECT().RevokeAllTokens(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, 1).Return(nil)
				mockConfig.EXPECT().GetVerificationTokenExpiry().Return(1200)
				mockRepo.EXPECT().CreateToken(ctx, gomock.Any()).Return(1, nil)
				mockConfig.EXPECT().GetVerificationLink().Return("http://example.com/verify?token={{token}}")
				mockUtils.EXPECT().GenerateString(25).Return("mock-token")
				mockMsg.EXPECT().PublishVerificationEmail("john@example.com", constant.USER_ACTIVATION_EMAIL_SUBJECT, "John", "http://example.com/verify?token=mock-token").Return(nil)
			},
			wantErr: false,
			wantMsg: "Activation Send Succefully.Please activate your account",
		},
		{
			name: "email already verified",
			args: args{req: domain.UserResendVerificationClientRequest{Email: "verified@example.com"}},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfig *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmail(ctx, "verified@example.com").Return(domain.User{Id: 2, Email: "verified@example.com", EmailVerified: true}, nil)
			},
			wantErr: true,
			wantMsg: "Your email is already verified",
		},
		{
			name: "publish email fails",
			args: args{req: domain.UserResendVerificationClientRequest{Email: "fail@example.com"}},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, mockLogger *mocks.MockLogger, mockConfig *mocks.MockUser, mockUtils *mocks.MockUtils) {
				mockRepo.EXPECT().GetUserByEmail(ctx, "fail@example.com").Return(domain.User{Id: 5, Email: "fail@example.com", Name: "Fail", EmailVerified: false}, nil)
				mockRepo.EXPECT().RevokeAllTokens(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, 5).Return(nil)
				mockConfig.EXPECT().GetVerificationTokenExpiry().Return(1200)
				mockRepo.EXPECT().CreateToken(ctx, gomock.Any()).Return(1, nil)
				mockConfig.EXPECT().GetVerificationLink().Return("http://example.com/verify?token={{token}}")
				mockUtils.EXPECT().GenerateString(25).Return("mock-token")
				mockMsg.EXPECT().PublishVerificationEmail("fail@example.com", constant.USER_ACTIVATION_EMAIL_SUBJECT, "Fail", "http://example.com/verify?token=mock-token").Return(assert.AnError)
				mockLogger.EXPECT().Errorw(ctx, "publish_verification_email failed", "userId", 5, "error", assert.AnError.Error(), "code", http.StatusInternalServerError, "exception", constant.NetworkException)
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
			mockConfig := mocks.NewMockUser(ctrl)
			mockUtils := mocks.NewMockUtils(ctrl)
			mockOAuthProvider := mocks.NewMockOAuthProvider(ctrl)

			tt.setupMocks(ctx, mockRepo, mockMsg, mockLogger, mockConfig, mockUtils)

			uc := New(mockLogger, mockToken, mockMsg, mockRepo, mockOAuthProvider, mockUtils, "myapp", mockConfig)

			resp, errRes := uc.ResendVerification(ctx, tt.args.req)

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
