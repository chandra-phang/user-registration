package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chandra-phang/sawit-pro/apperror"
	"github.com/chandra-phang/sawit-pro/handler/middleware"
	"github.com/chandra-phang/sawit-pro/model"
	"github.com/chandra-phang/sawit-pro/repository"
	"github.com/chandra-phang/sawit-pro/utils"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// UserRegister
func Test_UserRegister_Success(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)

	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), "+628123456789").
		Return(nil, apperror.ErrObjectNotExists)
	mockRepo.EXPECT().
		CreateUser(gomock.Any(), gomock.Any()).
		Return(nil)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{
		"name": "agus",
		"phoneNumber": "+628123456789",
		"password": "ABC123!"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"id":`)
	assert.NotContains(t, rec.Body.String(), `"error:"`)
}

func Test_UserRegister_ReturnError_WhenRequestBodyIsInvalid(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"id":`)
	assert.Contains(t, rec.Body.String(), `{"error":"invalid request body"}`)
}

func Test_UserRegister_ReturnError_WhenRequestBodyIsEmpty(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"id":`)
	assert.Contains(t, rec.Body.String(), `"error":"Name is required, Password is required, PhoneNumber is required"`)
}

func Test_UserRegister_ReturnError_WhenNameIsShorterThan3Chars(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{
		"name": "ag",
		"phoneNumber": "+628123456789",
		"password": "ABC123!"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"id":`)
	assert.Contains(t, rec.Body.String(), `{"error":"Name should be minimum 3 chars length"}`)
}

func Test_UserRegister_ReturnError_WhenNameIsLongerThan60Chars(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{
		"name": "Supercalifragilisticexpialidocious-Is-Awesome-And-Even-More-Awesome-Than-You-Can-Imagine",
		"phoneNumber": "+628123456789",
		"password": "ABC123!"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"id":`)
	assert.Contains(t, rec.Body.String(), `{"error":"Name should be maximum 60 chars length"}`)
}

func Test_UserRegister_ReturnError_WhenPasswordIsShorterThan6Chars(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{
		"name": "agus",
		"phoneNumber": "+628123456789",
		"password": "ABC"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"id":`)
	assert.Contains(t, rec.Body.String(), `{"error":"Password should be minimum 6 chars length"}`)
}

func Test_UserRegister_ReturnError_WhenPasswordIsLongerThan64Chars(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{
		"name": "agus",
		"phoneNumber": "+628123456789",
		"password": "Supercalifragilisticexpialidocious-Is-Awesome-And-Even-More-Awesome-Than-You-Can-Imagine"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"id":`)
	assert.Contains(t, rec.Body.String(), `{"error":"Password should be maximum 64 chars length"}`)
}

func Test_UserRegister_ReturnError_WhenPasswordIsNotSatisfyRules(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{
		"name": "agus",
		"phoneNumber": "+628123456789",
		"password": "ABC123"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"id":`)
	assert.Contains(t, rec.Body.String(), `{"error":"password should contain at least 1 capital characters AND 1 number AND 1 special (non-alpha-numeric) characters"}`)
}

func Test_UserRegister_ReturnError_WhenPhonenNumberIsShorterThan10Chars(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{
		"name": "agus",
		"phoneNumber": "+62812",
		"password": "ABC123!"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"id":`)
	assert.Contains(t, rec.Body.String(), `{"error":"PhoneNumber should be minimum 10 chars length"}`)
}

func Test_UserRegister_ReturnError_WhenPhoneNumberIsLongerThan13Chars(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{
		"name": "agus",
		"phoneNumber": "+62812345678910",
		"password": "ABC123!"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"id":`)
	assert.Contains(t, rec.Body.String(), `{"error":"PhoneNumber should be maximum 13 chars length"}`)
}

func Test_UserRegister_ReturnError_WhenPhoneNumberIsNotSatisfyRules(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{
		"name": "agus",
		"phoneNumber": "08123456789",
		"password": "ABC123!"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"id":`)
	assert.Contains(t, rec.Body.String(), `{"error":"Phone number must start with country code \"+62\""}`)
}

func Test_UserRegister_ReturnError_WhenGetUserByPhoneNumberIsFailed(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), "+628123456789").
		Return(nil, apperror.ErrGetRecordFailed)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{
		"name": "agus",
		"phoneNumber": "+628123456789",
		"password": "ABC123!"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"id":`)
	assert.Contains(t, rec.Body.String(), `{"error":"get record failed"}`)
}

func Test_UserRegister_ReturnError_WhenPhoneNumberIsAlreadyRegistered(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)

	existingUser := model.User{
		ID:          "user-id",
		Name:        "adi",
		PhoneNumber: "+628123456789",
	}
	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), "+628123456789").
		Return(&existingUser, nil)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{
		"name": "agus",
		"phoneNumber": "+628123456789",
		"password": "ABC123!"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"id":`)
	assert.Contains(t, rec.Body.String(), `{"error":"duplicate record found"}`)
}

func Test_UserRegister_ReturnError_WhenCreateUserIsFailed(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)

	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), "+628123456789").
		Return(nil, apperror.ErrObjectNotExists)
	mockRepo.EXPECT().
		CreateUser(gomock.Any(), gomock.Any()).
		Return(apperror.ErrCreateRecordFailed)

	opts := NewServerOptions{
		Repository: mockRepo,
	}

	requestBody := `{
		"name": "agus",
		"phoneNumber": "+628123456789",
		"password": "ABC123!"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserRegister(c)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"id":`)
	assert.Contains(t, rec.Body.String(), `{"error":"create record failed"}`)
}

// UserLogin
func Test_UserLogin_Success(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	password := "ABC123!"
	hashPassword, _ := utils.GenerateHash(password)
	mockUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456789",
		Password:    hashPassword,
	}
	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), mockUser.PhoneNumber).
		Return(&mockUser, nil)
	mockJwtSvc.EXPECT().
		GenerateToken(mockUser.ID).
		Return("token-string", nil)
	mockRepo.EXPECT().
		CreateLoginLog(gomock.Any(), gomock.Any()).
		Return(nil)

	requestBody := `{
		"phoneNumber": "+628123456789",
		"password": "ABC123!"
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserLogin(c)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `{"id":"user-id","token":"token-string"}`)
}

func Test_UserLogin_ReturnError_WhenRequestBodyIsInvalid(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)

	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	requestBody := `{`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserLogin(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"id":"user-id"`)
	assert.Contains(t, rec.Body.String(), `{"error":"invalid request body"}`)
}

func Test_UserLogin_ReturnError_WhenRequestBodyIsEmpty(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)

	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	requestBody := `{}`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserLogin(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"id":"user-id"`)
	assert.Contains(t, rec.Body.String(), `{"error":"Password is required, PhoneNumber is required"}`)
}

func Test_UserLogin_ReturnError_WhenPhoneNumberIsNotRegistered(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)

	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), "+628123456789").
		Return(nil, apperror.ErrGetRecordFailed)

	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	requestBody := `{
		"phoneNumber": "+628123456789",
		"password": "ABC123!"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserLogin(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"id":"user-id"`)
	assert.Contains(t, rec.Body.String(), `{"error":"get record failed"}`)
}

func Test_UserLogin_ReturnError_WhenPasswordIsNotMatch(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)

	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	password := "ABC123!"
	hashPassword, _ := utils.GenerateHash(password)
	mockUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456789",
		Password:    hashPassword,
	}
	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), "+628123456789").
		Return(&mockUser, nil)

	requestBody := `{
		"phoneNumber": "+628123456789",
		"password": "wrong-password"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserLogin(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"id":"user-id"`)
	assert.Contains(t, rec.Body.String(), `{"error":"invalid phone_number or password"}`)
}

func Test_UserLogin_ReturnError_WhenGenerateTokenIsFailed(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	password := "ABC123!"
	hashPassword, _ := utils.GenerateHash(password)
	mockUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456789",
		Password:    hashPassword,
	}
	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), mockUser.PhoneNumber).
		Return(&mockUser, nil)
	mockJwtSvc.EXPECT().
		GenerateToken(mockUser.ID).
		Return("", errors.New("key is invalid"))

	requestBody := `{
		"phoneNumber": "+628123456789",
		"password": "ABC123!"
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserLogin(c)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"id":"user-id"`)
	assert.Contains(t, rec.Body.String(), `{"error":"key is invalid"`)
}

func Test_UserLogin_ReturnError_WhenCreateLoginLogIsFailed(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	password := "ABC123!"
	hashPassword, _ := utils.GenerateHash(password)
	mockUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456789",
		Password:    hashPassword,
	}
	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), mockUser.PhoneNumber).
		Return(&mockUser, nil)
	mockJwtSvc.EXPECT().
		GenerateToken(mockUser.ID).
		Return("token-string", nil)
	mockRepo.EXPECT().
		CreateLoginLog(gomock.Any(), gomock.Any()).
		Return(apperror.ErrCreateRecordFailed)

	requestBody := `{
		"phoneNumber": "+628123456789",
		"password": "ABC123!"
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UserLogin(c)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"id":"user-id"`)
	assert.Contains(t, rec.Body.String(), `{"error":"create record failed"}`)
}

func Test_GetUser_Success(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	mockUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456789",
	}
	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "user-id"}, nil)
	mockRepo.EXPECT().
		GetUserByID(gomock.Any(), mockUser.ID).
		Return(&mockUser, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.GetUser(c)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `{"name":"user-name","phoneNumber":"+628123456789"}`)
}

func Test_GetUser_ReturnError_WhenBearerTokenIsInvalid(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(nil, errors.New("invalid token"))

	req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.GetUser(c)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"name":`)
	assert.Contains(t, rec.Body.String(), `{"error":"invalid token"}`)
}

func Test_GetUser_ReturnError_WhenUserIdIsNotIdentified(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "invalid-user-id"}, nil)
	mockRepo.EXPECT().
		GetUserByID(gomock.Any(), "invalid-user-id").
		Return(nil, apperror.ErrObjectNotExists)

	req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.GetUser(c)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"name":"`)
	assert.Contains(t, rec.Body.String(), `{"error":"object does not exist"`)
}

func Test_UpdateUser_Success(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	mockUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456789",
	}
	updatedMockUser := model.User{
		ID:          "user-id",
		Name:        "agus",
		PhoneNumber: "+628123456780",
	}
	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "user-id"}, nil)
	mockRepo.EXPECT().
		GetUserByID(gomock.Any(), mockUser.ID).
		Return(&mockUser, nil)
	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), updatedMockUser.PhoneNumber).
		Return(&mockUser, nil)
	mockRepo.EXPECT().
		UpdateUser(gomock.Any(), updatedMockUser).
		Return(nil)

	requestBody := `{
		"name": "agus",
		"phoneNumber": "+628123456780"
	}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/users/me", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UpdateUser(c)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `{"name":"agus","phoneNumber":"+628123456780"}`)
}

func Test_UpdateUser_ReturnError_WhenBearerTokenIsInvalid(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}
	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(nil, errors.New("invalid token"))

	requestBody := `{
		"name": "agus",
		"phoneNumber": "+628123456780"
	}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/users/me", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UpdateUser(c)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"name":`)
	assert.Contains(t, rec.Body.String(), `{"error":"invalid token"}`)
}

func Test_UpdateUser_ReturnError_WhenRequestBodyIsInvalid(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}
	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "user-id"}, nil)

	requestBody := `{`
	req := httptest.NewRequest(http.MethodPatch, "/v1/users/me", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UpdateUser(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"name":`)
	assert.Contains(t, rec.Body.String(), `{"error":"invalid request body"}`)
}

func Test_UpdateUser_ReturnError_WhenRequestBodyIsEmpty(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}
	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "user-id"}, nil)

	requestBody := `{}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/users/me", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UpdateUser(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"name":`)
	assert.Contains(t, rec.Body.String(), `{"error":"invalid request body"}`)
}

func Test_UpdateUser_ReturnError_WhenPhoneNumberIsShorterThan10Chars(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}
	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "user-id"}, nil)

	requestBody := `{"phoneNumber": "+6281234"}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/users/me", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UpdateUser(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"name":`)
	assert.Contains(t, rec.Body.String(), `{"error":"PhoneNumber should be minimum 10 chars length"}`)
}

func Test_UpdateUser_ReturnError_WhenPhoneNumberIsLongerThan10Chars(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}
	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "user-id"}, nil)

	requestBody := `{"phoneNumber": "+62812345678910"}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/users/me", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UpdateUser(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"name":`)
	assert.Contains(t, rec.Body.String(), `{"error":"PhoneNumber should be maximum 13 chars length"}`)
}

func Test_UpdateUser_ReturnError_WhenPhoneNumberIsNotSatisfyRules(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	mockUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456789",
	}
	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "user-id"}, nil)
	mockRepo.EXPECT().
		GetUserByID(gomock.Any(), "user-id").
		Return(&mockUser, nil)

	requestBody := `{"phoneNumber": "08123456789"}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/users/me", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UpdateUser(c)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"name":`)
	assert.Contains(t, rec.Body.String(), `{"error":"Phone number must start with country code \"+62\""}`)
}

func Test_UpdateUser_ReturnError_WhenUserIdIsUnidentified(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}
	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "invalid-user-id"}, nil)
	mockRepo.EXPECT().
		GetUserByID(gomock.Any(), "invalid-user-id").
		Return(nil, apperror.ErrObjectNotExists)

	requestBody := `{"phoneNumber": "+628123456789"}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/users/me", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UpdateUser(c)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"name":`)
	assert.Contains(t, rec.Body.String(), `{"error":"object does not exist"}`)
}

func Test_UpdateUser_ReturnError_WhenGetUserByPhoneNumberIsFailed(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	mockUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456789",
	}

	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "user-id"}, nil)
	mockRepo.EXPECT().
		GetUserByID(gomock.Any(), mockUser.ID).
		Return(&mockUser, nil)
	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), "+628123456780").
		Return(nil, apperror.ErrGetRecordFailed)

	requestBody := `{"phoneNumber": "+628123456780"}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/users/me", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UpdateUser(c)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"name":`)
	assert.Contains(t, rec.Body.String(), `{"error":"get record failed"}`)
}

func Test_UpdateUser_ReturnError_WhenUpdatedPhoneNumberIsAlreadyRegisteredByDifferentUser(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	mockUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456789",
	}
	differentUser := model.User{
		ID:          "different-user-id",
		Name:        "different-user-name",
		PhoneNumber: "+628123456780",
	}

	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "user-id"}, nil)
	mockRepo.EXPECT().
		GetUserByID(gomock.Any(), mockUser.ID).
		Return(&mockUser, nil)
	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), differentUser.PhoneNumber).
		Return(&differentUser, nil)

	requestBody := `{"phoneNumber": "+628123456780"}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/users/me", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UpdateUser(c)

	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"name":`)
	assert.Contains(t, rec.Body.String(), `{"error":"duplicate record found"}`)
}

func Test_UpdateUser_ReturnSuccess_WithOnlyUpdateName(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	mockUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456789",
	}
	updatedUser := model.User{
		ID:          "user-id",
		Name:        "agus",
		PhoneNumber: "+628123456789",
	}
	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "user-id"}, nil)
	mockRepo.EXPECT().
		GetUserByID(gomock.Any(), mockUser.ID).
		Return(&mockUser, nil)
	mockRepo.EXPECT().
		UpdateUser(gomock.Any(), updatedUser).
		Return(nil)

	requestBody := `{"name": "agus"}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/users/me", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UpdateUser(c)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `{"name":"agus","phoneNumber":"+628123456789"}`)
	assert.NotContains(t, rec.Body.String(), `{"error":`)
}

func Test_UpdateUser_ReturnSuccess_WithOnlyUpdatePhoneNumber(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	mockUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456789",
	}
	updatedUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456780",
	}
	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "user-id"}, nil)
	mockRepo.EXPECT().
		GetUserByID(gomock.Any(), mockUser.ID).
		Return(&mockUser, nil)
	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), updatedUser.PhoneNumber).
		Return(nil, apperror.ErrObjectNotExists)
	mockRepo.EXPECT().
		UpdateUser(gomock.Any(), updatedUser).
		Return(nil)

	requestBody := `{"phoneNumber": "+628123456780"}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/users/me", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UpdateUser(c)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `{"name":"user-name","phoneNumber":"+628123456780"}`)
	assert.NotContains(t, rec.Body.String(), `{"error":`)
}

func Test_UpdateUser_ReturnError_WhenUpdateUserIsFailed(t *testing.T) {
	e := echo.New()

	ctrl := gomock.NewController(t)
	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	mockJwtSvc := middleware.NewMockIJwtService(ctrl)
	opts := NewServerOptions{
		Repository: mockRepo,
		JwtService: mockJwtSvc,
	}

	mockUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456789",
	}
	updatedUser := model.User{
		ID:          "user-id",
		Name:        "user-name",
		PhoneNumber: "+628123456780",
	}
	mockJwtSvc.EXPECT().
		Auth(gomock.Any()).
		Return(&middleware.User{ID: "user-id"}, nil)
	mockRepo.EXPECT().
		GetUserByID(gomock.Any(), mockUser.ID).
		Return(&mockUser, nil)
	mockRepo.EXPECT().
		GetUserByPhoneNumber(gomock.Any(), updatedUser.PhoneNumber).
		Return(nil, apperror.ErrObjectNotExists)
	mockRepo.EXPECT().
		UpdateUser(gomock.Any(), updatedUser).
		Return(apperror.ErrUpdateRecordFailed)

	requestBody := `{"phoneNumber": "+628123456780"}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/users/me", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	server := NewServer(opts)
	server.UpdateUser(c)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), `{"name":"user-name","phoneNumber":"+628123456780"}`)
	assert.Contains(t, rec.Body.String(), `{"error":"update record failed"}`)
}
