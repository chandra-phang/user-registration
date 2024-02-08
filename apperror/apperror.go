package apperror

import "errors"

var (
	// DB
	ErrObjectNotExists      = errors.New("object does not exist")
	ErrCreateRecordFailed   = errors.New("create record failed")
	ErrGetRecordFailed      = errors.New("get record failed")
	ErrScanRecordFailed     = errors.New("scan record failed")
	ErrUpdateRecordFailed   = errors.New("update record failed")
	ErrDeleteRecordFailed   = errors.New("delete record failed")
	ErrDuplicateRecordFound = errors.New("duplicate record found")

	// Request
	ErrInvalidRequestBody = errors.New("invalid request body")

	// User
	ErrInvalidPhoneNumberOrPassword = errors.New("invalid phone_number or password")
)
