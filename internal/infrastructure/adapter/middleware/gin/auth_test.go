package gin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/loganrk/user-vault/test/mocks"
)

// Helper to create a request with Authorization header
func newRequestWithAuthHeader(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestValidateApiKey(t *testing.T) {
	tests := []struct {
		name           string
		apiKeys        []string
		providedToken  string
		expectedStatus int
	}{
		{
			name:           "missing token",
			apiKeys:        []string{"key1"},
			providedToken:  "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid token",
			apiKeys:        []string{"key1"},
			providedToken:  "invalid",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "valid token",
			apiKeys:        []string{"valid-api-key"},
			providedToken:  "valid-api-key",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockToken := mocks.NewMockToken(ctrl)
			mw := New(tt.apiKeys, mockToken)

			handler := mw.ValidateApiKey()

			// Create request
			req := newRequestWithAuthHeader(tt.providedToken)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func TestValidateRefreshToken(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		mockSetup      func(m *mocks.MockToken)
		expectedStatus int
	}{
		{
			name:           "missing token",
			token:          "",
			mockSetup:      nil,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:  "invalid token data",
			token: "bad-token",
			mockSetup: func(m *mocks.MockToken) {
				m.EXPECT().GetRefreshTokenData("bad-token").Return(0, time.Time{}, nil)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:  "expired token",
			token: "expired-token",
			mockSetup: func(m *mocks.MockToken) {
				m.EXPECT().GetRefreshTokenData("expired-token").Return(123, time.Now().Add(-time.Hour), nil)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:  "internal error",
			token: "error-token",
			mockSetup: func(m *mocks.MockToken) {
				m.EXPECT().GetRefreshTokenData("error-token").Return(0, time.Time{}, errors.New("some error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:  "valid token",
			token: "valid-token",
			mockSetup: func(m *mocks.MockToken) {
				m.EXPECT().GetRefreshTokenData("valid-token").Return(123, time.Now().Add(time.Hour), nil)
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockToken := mocks.NewMockToken(ctrl)
			if tt.mockSetup != nil {
				tt.mockSetup(mockToken)
			}

			mw := New([]string{}, mockToken)
			handler := mw.ValidateRefreshToken()

			req := newRequestWithAuthHeader(tt.token)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}
