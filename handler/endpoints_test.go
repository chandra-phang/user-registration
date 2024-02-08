package handler

// func Test_UserRegister(t *testing.T) {
// 	e := echo.New()

// 	ctrl := gomock.NewController(t)
// 	mockRepo := mock_repository.NewMockRepositoryInterface(ctrl)
// 	mockJwtService := mock_middleware.NewMockIJwtService(ctrl)

// 	opts := NewServerOptions{
// 		Repository: mockRepo,
// 		JwtService: mockJwtService,
// 	}

// 	requestBody := `{
// 		"name": "agus",
// 		"phoneNumber": "+628123456789",
// 		"password": "ABC123!"
// 	}`
// 	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(requestBody))
// 	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

// 	rec := httptest.NewRecorder()
// 	c := e.NewContext(req, rec)

// 	server := NewServer(opts)
// 	server.UserRegister(c)

// 	assert.Equal(t, http.StatusOK, rec.Code)
// 	assert.Equal(t, "", rec.Body.String())
// }
