// Code generated by MockGen. DO NOT EDIT.
// Source: assuan.go

// Package mock is a generated GoMock package.
package mock

import (
	crypto "crypto"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockKeyService is a mock of KeyService interface.
type MockKeyService struct {
	ctrl     *gomock.Controller
	recorder *MockKeyServiceMockRecorder
}

// MockKeyServiceMockRecorder is the mock recorder for MockKeyService.
type MockKeyServiceMockRecorder struct {
	mock *MockKeyService
}

// NewMockKeyService creates a new mock instance.
func NewMockKeyService(ctrl *gomock.Controller) *MockKeyService {
	mock := &MockKeyService{ctrl: ctrl}
	mock.recorder = &MockKeyServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockKeyService) EXPECT() *MockKeyServiceMockRecorder {
	return m.recorder
}

// GetDecrypter mocks base method.
func (m *MockKeyService) GetDecrypter(arg0 []byte) (crypto.Decrypter, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDecrypter", arg0)
	ret0, _ := ret[0].(crypto.Decrypter)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetDecrypter indicates an expected call of GetDecrypter.
func (mr *MockKeyServiceMockRecorder) GetDecrypter(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDecrypter", reflect.TypeOf((*MockKeyService)(nil).GetDecrypter), arg0)
}

// GetSigner mocks base method.
func (m *MockKeyService) GetSigner(arg0 []byte) (crypto.Signer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSigner", arg0)
	ret0, _ := ret[0].(crypto.Signer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSigner indicates an expected call of GetSigner.
func (mr *MockKeyServiceMockRecorder) GetSigner(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSigner", reflect.TypeOf((*MockKeyService)(nil).GetSigner), arg0)
}

// HaveKey mocks base method.
func (m *MockKeyService) HaveKey(arg0 [][]byte) (bool, []byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HaveKey", arg0)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].([]byte)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// HaveKey indicates an expected call of HaveKey.
func (mr *MockKeyServiceMockRecorder) HaveKey(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HaveKey", reflect.TypeOf((*MockKeyService)(nil).HaveKey), arg0)
}

// Name mocks base method.
func (m *MockKeyService) Name() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Name")
	ret0, _ := ret[0].(string)
	return ret0
}

// Name indicates an expected call of Name.
func (mr *MockKeyServiceMockRecorder) Name() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Name", reflect.TypeOf((*MockKeyService)(nil).Name))
}