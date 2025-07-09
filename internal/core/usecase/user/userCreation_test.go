package user

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/loganrk/user-vault/internal/constant"
	"github.com/loganrk/user-vault/internal/core/domain"
	"github.com/loganrk/user-vault/test/mocks"
)

type mocksSetup func(
	ctx context.Context,
	mockRepo *mocks.MockRepositoryMySQL,
	mockMsg *mocks.MockMessager,
	mockLogger *mocks.MockLogger,
	mockConfigUser *mocks.MockUser,
)

func TestRegister_success(t *testing.T) {
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
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, _ *mocks.MockLogger, mockConfigUser *mocks.MockUser) {
				mockRepo.EXPECT().
					GetUserByEmailOrPhone(ctx, "alice@example.com", "").
					Return(domain.User{}, nil)

				mockRepo.EXPECT().
					CreateUser(ctx, gomock.Any()).
					Return(int(1), nil)

				mockRepo.EXPECT().
					GetUserByUserID(ctx, int(1)).
					Return(domain.User{Id: 1, Name: "Alice", Email: "alice@example.com"}, nil)

				mockRepo.EXPECT().
					CreateToken(ctx, gomock.Any()).
					Return(0, nil)

				mockMsg.EXPECT().
					PublishVerificationEmail("alice@example.com", constant.USER_ACTIVATION_EMAIL_SUBJECT, "Alice", gomock.Any()).
					Return(nil)

				mockConfigUser.EXPECT().
					GetPasswordHashCost().
					Return(12)

				mockRepo.EXPECT().
					RevokeAllTokens(ctx, gomock.Any(), gomock.Any()).
					Return(nil)

				mockConfigUser.EXPECT().
					GetVerificationTokenExpiry().
					Return(1200)

				mockConfigUser.EXPECT().
					GetVerificationLink().
					Return("")

			},
			wantErr: false,
			wantMsg: "Account created successfully.",
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

			// Setup mocks for this test case
			tt.setupMocks(ctx, mockRepo, mockMsg, mockLogger, mockConfigUser)

			resp, errRes := uc.Register(ctx, tt.args.req)

			if tt.wantErr {
				assert.NotEmpty(t, errRes.Err)
				assert.Equal(t, tt.wantMsg, errRes.Message)
			} else {
				assert.Empty(t, errRes.Err)
				assert.Equal(t, tt.wantMsg, resp.Message)
			}
		})
	}
}

func TestVerifyUser_Success_EmailVerification(t *testing.T) {
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
			name: "success email registration",
			args: args{
				req: domain.UserVerifyClientRequest{
					Email: "alice@example.com",
					Token: "valid-token",
				},
			},
			setupMocks: func(ctx context.Context, mockRepo *mocks.MockRepositoryMySQL, mockMsg *mocks.MockMessager, _ *mocks.MockLogger, mockConfigUser *mocks.MockUser) {

				mockRepo.EXPECT().
					GetUserByEmail(ctx, "alice@example.com").
					Return(domain.User{
						Id:            1,
						Email:         "alice@example.com",
						EmailVerified: false,
					}, nil)

				// Expect UpdateEmailVerfied
				mockRepo.EXPECT().
					UpdateEmailVerfied(ctx, 1).
					Return(nil)

				mockRepo.EXPECT().
					GetUserLastTokenByUserId(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, 1).
					Return(domain.UserTokens{
						Id:        1,
						Token:     "valid-token",
						Revoked:   false,
						ExpiresAt: time.Now().Add(10 * time.Second),
					}, nil)

				// Expect RevokeToken
				mockRepo.EXPECT().
					RevokeToken(ctx, 1).
					Return(nil)

			},
			wantErr: false,
			wantMsg: "User account activated successfully.",
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

			// Setup mocks for this test case
			tt.setupMocks(ctx, mockRepo, mockMsg, mockLogger, mockConfigUser)

			resp, errRes := uc.VerifyUser(ctx, tt.args.req)

			if tt.wantErr {
				assert.NotEmpty(t, errRes.Err)
				assert.Equal(t, tt.wantMsg, errRes.Message)
			} else {
				assert.Empty(t, errRes.Err)
				assert.Equal(t, tt.wantMsg, resp.Message)
			}
		})
	}

}
