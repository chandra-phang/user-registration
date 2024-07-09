package handler

import (
	"net/http"

	"github.com/chandra-phang/user-registration/apperror"
	"github.com/chandra-phang/user-registration/generated"
	"github.com/chandra-phang/user-registration/model"
	"github.com/chandra-phang/user-registration/utils"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

// (POST /v1/users)
func (s *Server) UserRegister(ctx echo.Context) error {
	var requestBody generated.UserRegisterRequestDTO
	err := ctx.Bind(&requestBody)
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: apperror.ErrInvalidRequestBody.Error()}
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	validate := validator.New()
	err = validate.Struct(requestBody)
	if err != nil {
		humanizedErr := utils.TryTranslateValidationErrors(err)
		resp := generated.ErrorMessageResponseDTO{Error: humanizedErr.Error()}
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if !utils.IsValidPhoneNumber(requestBody.PhoneNumber) {
		errorMessage := `Phone number must start with country code "+62"`
		resp := generated.ErrorMessageResponseDTO{Error: errorMessage}
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if !utils.IsValidPassword(requestBody.Password) {
		errorMessage := "password should contain at least 1 capital characters AND 1 number AND 1 special (non-alpha-numeric) characters"
		resp := generated.ErrorMessageResponseDTO{Error: errorMessage}
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	existingUser, err := s.Repository.GetUserByPhoneNumber(ctx.Request().Context(), requestBody.PhoneNumber)
	if err != nil && err != apperror.ErrObjectNotExists {
		resp := generated.ErrorMessageResponseDTO{Error: err.Error()}
		return ctx.JSON(http.StatusInternalServerError, resp)
	}

	if existingUser != nil && existingUser.ID != "" {
		resp := generated.ErrorMessageResponseDTO{Error: apperror.ErrDuplicateRecordFound.Error()}
		return ctx.JSON(http.StatusConflict, resp)
	}

	password, err := utils.GenerateHash(requestBody.Password)
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: "hash password is failed"}
		return ctx.JSON(http.StatusInternalServerError, resp)
	}

	user := model.User{
		ID:          utils.GenerateUUID(),
		Name:        requestBody.Name,
		PhoneNumber: requestBody.PhoneNumber,
		Password:    password,
	}

	err = s.Repository.CreateUser(ctx.Request().Context(), user)
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: err.Error()}
		return ctx.JSON(http.StatusInternalServerError, resp)
	}

	return ctx.JSON(http.StatusOK, generated.UserRegisterResponseDTO{Id: user.ID})
}

// (POST /v1/auth/login)
func (s *Server) UserLogin(ctx echo.Context) error {
	var requestBody generated.UserLoginRequestDTO
	err := ctx.Bind(&requestBody)
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: apperror.ErrInvalidRequestBody.Error()}
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	validate := validator.New()
	err = validate.Struct(requestBody)
	if err != nil {
		humanizedErr := utils.TryTranslateValidationErrors(err)
		resp := generated.ErrorMessageResponseDTO{Error: humanizedErr.Error()}
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	user, err := s.Repository.GetUserByPhoneNumber(ctx.Request().Context(), requestBody.PhoneNumber)
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: err.Error()}
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(requestBody.Password))
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: apperror.ErrInvalidPhoneNumberOrPassword.Error()}
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	token, err := s.JwtService.GenerateToken(user.ID)
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: err.Error()}
		return ctx.JSON(http.StatusInternalServerError, resp)
	}

	loginLog := model.LoginLog{
		ID:   utils.GenerateUUID(),
		User: model.User{ID: user.ID},
	}
	err = s.Repository.CreateLoginLog(ctx.Request().Context(), loginLog)
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: err.Error()}
		return ctx.JSON(http.StatusInternalServerError, resp)
	}

	return ctx.JSON(http.StatusOK, generated.UserLoginResponseDTO{Id: user.ID, Token: token})
}

// (GET /v1/users/me)
func (s *Server) GetUser(ctx echo.Context) error {
	tokenUser, err := s.JwtService.Auth(ctx.Request())
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: err.Error()}
		return ctx.JSON(http.StatusForbidden, resp)
	}

	user, err := s.Repository.GetUserByID(ctx.Request().Context(), tokenUser.ID)
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: err.Error()}
		return ctx.JSON(http.StatusForbidden, resp)
	}

	return ctx.JSON(http.StatusOK, generated.UserProfileResponseDTO{Name: user.Name, PhoneNumber: user.PhoneNumber})
}

// (PATCH /v1/users/me)
func (s *Server) UpdateUser(ctx echo.Context) error {
	tokenUser, err := s.JwtService.Auth(ctx.Request())
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: err.Error()}
		return ctx.JSON(http.StatusForbidden, resp)
	}

	var requestBody generated.UserUpdateRequestDTO
	err = ctx.Bind(&requestBody)
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: apperror.ErrInvalidRequestBody.Error()}
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	validate := validator.New()
	err = validate.Struct(requestBody)
	if err != nil {
		humanizedErr := utils.TryTranslateValidationErrors(err)
		resp := generated.ErrorMessageResponseDTO{Error: humanizedErr.Error()}
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if requestBody.PhoneNumber == "" && requestBody.Name == "" {
		resp := generated.ErrorMessageResponseDTO{Error: apperror.ErrInvalidRequestBody.Error()}
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	user, err := s.Repository.GetUserByID(ctx.Request().Context(), tokenUser.ID)
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: err.Error()}
		return ctx.JSON(http.StatusForbidden, resp)
	}

	if requestBody.PhoneNumber != "" {
		if !utils.IsValidPhoneNumber(requestBody.PhoneNumber) {
			errorMessage := `Phone number must start with country code "+62"`
			resp := generated.ErrorMessageResponseDTO{Error: errorMessage}
			return ctx.JSON(http.StatusBadRequest, resp)
		}

		existingUser, err := s.Repository.GetUserByPhoneNumber(ctx.Request().Context(), requestBody.PhoneNumber)
		if err != nil && err != apperror.ErrObjectNotExists {
			resp := generated.ErrorMessageResponseDTO{Error: err.Error()}
			return ctx.JSON(http.StatusInternalServerError, resp)
		}

		if existingUser != nil && existingUser.ID != user.ID {
			resp := generated.ErrorMessageResponseDTO{Error: apperror.ErrDuplicateRecordFound.Error()}
			return ctx.JSON(http.StatusConflict, resp)
		}
	}

	if requestBody.Name != "" {
		user.Name = requestBody.Name
	}
	if requestBody.PhoneNumber != "" {
		user.PhoneNumber = requestBody.PhoneNumber
	}

	err = s.Repository.UpdateUser(ctx.Request().Context(), *user)
	if err != nil {
		resp := generated.ErrorMessageResponseDTO{Error: err.Error()}
		return ctx.JSON(http.StatusInternalServerError, resp)
	}

	return ctx.JSON(http.StatusOK, generated.UserProfileResponseDTO{Name: user.Name, PhoneNumber: user.PhoneNumber})
}
