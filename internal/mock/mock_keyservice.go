// Code generated by MockGen. DO NOT EDIT.
// Source: keyservice.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockPINEntryService is a mock of PINEntryService interface.
type MockPINEntryService struct {
	ctrl     *gomock.Controller
	recorder *MockPINEntryServiceMockRecorder
}

// MockPINEntryServiceMockRecorder is the mock recorder for MockPINEntryService.
type MockPINEntryServiceMockRecorder struct {
	mock *MockPINEntryService
}

// NewMockPINEntryService creates a new mock instance.
func NewMockPINEntryService(ctrl *gomock.Controller) *MockPINEntryService {
	mock := &MockPINEntryService{ctrl: ctrl}
	mock.recorder = &MockPINEntryServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPINEntryService) EXPECT() *MockPINEntryServiceMockRecorder {
	return m.recorder
}

// GetPassphrase mocks base method.
func (m *MockPINEntryService) GetPassphrase(arg0, arg1 string, arg2 int) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPassphrase", arg0, arg1, arg2)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPassphrase indicates an expected call of GetPassphrase.
func (mr *MockPINEntryServiceMockRecorder) GetPassphrase(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPassphrase", reflect.TypeOf((*MockPINEntryService)(nil).GetPassphrase), arg0, arg1, arg2)
}