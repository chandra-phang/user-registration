// Code generated by MockGen. DO NOT EDIT.
// Source: interfaces.go

// Package repository is a generated GoMock package.
package repository

import (
	context "context"
	reflect "reflect"

	model "github.com/chandra-phang/user-registration/model"
	gomock "github.com/golang/mock/gomock"
)

// MockRepositoryInterface is a mock of RepositoryInterface interface.
type MockRepositoryInterface struct {
	ctrl     *gomock.Controller
	recorder *MockRepositoryInterfaceMockRecorder
}

// MockRepositoryInterfaceMockRecorder is the mock recorder for MockRepositoryInterface.
type MockRepositoryInterfaceMockRecorder struct {
	mock *MockRepositoryInterface
}

// NewMockRepositoryInterface creates a new mock instance.
func NewMockRepositoryInterface(ctrl *gomock.Controller) *MockRepositoryInterface {
	mock := &MockRepositoryInterface{ctrl: ctrl}
	mock.recorder = &MockRepositoryInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRepositoryInterface) EXPECT() *MockRepositoryInterfaceMockRecorder {
	return m.recorder
}

// CreateLoginLog mocks base method.
func (m *MockRepositoryInterface) CreateLoginLog(ctx context.Context, loginLog model.LoginLog) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateLoginLog", ctx, loginLog)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateLoginLog indicates an expected call of CreateLoginLog.
func (mr *MockRepositoryInterfaceMockRecorder) CreateLoginLog(ctx, loginLog interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateLoginLog", reflect.TypeOf((*MockRepositoryInterface)(nil).CreateLoginLog), ctx, loginLog)
}

// CreateUser mocks base method.
func (m *MockRepositoryInterface) CreateUser(ctx context.Context, user model.User) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUser", ctx, user)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateUser indicates an expected call of CreateUser.
func (mr *MockRepositoryInterfaceMockRecorder) CreateUser(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUser", reflect.TypeOf((*MockRepositoryInterface)(nil).CreateUser), ctx, user)
}

// GetUserByID mocks base method.
func (m *MockRepositoryInterface) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserByID", ctx, id)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserByID indicates an expected call of GetUserByID.
func (mr *MockRepositoryInterfaceMockRecorder) GetUserByID(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByID", reflect.TypeOf((*MockRepositoryInterface)(nil).GetUserByID), ctx, id)
}

// GetUserByPhoneNumber mocks base method.
func (m *MockRepositoryInterface) GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserByPhoneNumber", ctx, phoneNumber)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserByPhoneNumber indicates an expected call of GetUserByPhoneNumber.
func (mr *MockRepositoryInterfaceMockRecorder) GetUserByPhoneNumber(ctx, phoneNumber interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByPhoneNumber", reflect.TypeOf((*MockRepositoryInterface)(nil).GetUserByPhoneNumber), ctx, phoneNumber)
}

// UpdateUser mocks base method.
func (m *MockRepositoryInterface) UpdateUser(ctx context.Context, user model.User) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUser", ctx, user)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateUser indicates an expected call of UpdateUser.
func (mr *MockRepositoryInterfaceMockRecorder) UpdateUser(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*MockRepositoryInterface)(nil).UpdateUser), ctx, user)
}
