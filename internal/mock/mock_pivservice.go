// Code generated by MockGen. DO NOT EDIT.
// Source: list.go
//
// Generated by this command:
//
//	mockgen -source=list.go -destination=../../mock/mock_pivservice.go -package=mock
//

// Package mock is a generated GoMock package.
package mock

import (
	crypto "crypto"
	x509 "crypto/x509"
	reflect "reflect"

	securitykey "github.com/smlx/piv-agent/internal/securitykey"
	gomock "go.uber.org/mock/gomock"
)

// MockSecurityKey is a mock of SecurityKey interface.
type MockSecurityKey struct {
	ctrl     *gomock.Controller
	recorder *MockSecurityKeyMockRecorder
}

// MockSecurityKeyMockRecorder is the mock recorder for MockSecurityKey.
type MockSecurityKeyMockRecorder struct {
	mock *MockSecurityKey
}

// NewMockSecurityKey creates a new mock instance.
func NewMockSecurityKey(ctrl *gomock.Controller) *MockSecurityKey {
	mock := &MockSecurityKey{ctrl: ctrl}
	mock.recorder = &MockSecurityKeyMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSecurityKey) EXPECT() *MockSecurityKeyMockRecorder {
	return m.recorder
}

// AttestationCertificate mocks base method.
func (m *MockSecurityKey) AttestationCertificate() (*x509.Certificate, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AttestationCertificate")
	ret0, _ := ret[0].(*x509.Certificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AttestationCertificate indicates an expected call of AttestationCertificate.
func (mr *MockSecurityKeyMockRecorder) AttestationCertificate() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AttestationCertificate", reflect.TypeOf((*MockSecurityKey)(nil).AttestationCertificate))
}

// Card mocks base method.
func (m *MockSecurityKey) Card() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Card")
	ret0, _ := ret[0].(string)
	return ret0
}

// Card indicates an expected call of Card.
func (mr *MockSecurityKeyMockRecorder) Card() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Card", reflect.TypeOf((*MockSecurityKey)(nil).Card))
}

// Close mocks base method.
func (m *MockSecurityKey) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockSecurityKeyMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockSecurityKey)(nil).Close))
}

// Comment mocks base method.
func (m *MockSecurityKey) Comment(arg0 *securitykey.SlotSpec) string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Comment", arg0)
	ret0, _ := ret[0].(string)
	return ret0
}

// Comment indicates an expected call of Comment.
func (mr *MockSecurityKeyMockRecorder) Comment(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Comment", reflect.TypeOf((*MockSecurityKey)(nil).Comment), arg0)
}

// CryptoKeys mocks base method.
func (m *MockSecurityKey) CryptoKeys() []securitykey.CryptoKey {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CryptoKeys")
	ret0, _ := ret[0].([]securitykey.CryptoKey)
	return ret0
}

// CryptoKeys indicates an expected call of CryptoKeys.
func (mr *MockSecurityKeyMockRecorder) CryptoKeys() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CryptoKeys", reflect.TypeOf((*MockSecurityKey)(nil).CryptoKeys))
}

// PrivateKey mocks base method.
func (m *MockSecurityKey) PrivateKey(arg0 *securitykey.CryptoKey) (crypto.PrivateKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PrivateKey", arg0)
	ret0, _ := ret[0].(crypto.PrivateKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PrivateKey indicates an expected call of PrivateKey.
func (mr *MockSecurityKeyMockRecorder) PrivateKey(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PrivateKey", reflect.TypeOf((*MockSecurityKey)(nil).PrivateKey), arg0)
}

// SigningKeys mocks base method.
func (m *MockSecurityKey) SigningKeys() []securitykey.SigningKey {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SigningKeys")
	ret0, _ := ret[0].([]securitykey.SigningKey)
	return ret0
}

// SigningKeys indicates an expected call of SigningKeys.
func (mr *MockSecurityKeyMockRecorder) SigningKeys() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SigningKeys", reflect.TypeOf((*MockSecurityKey)(nil).SigningKeys))
}

// StringsGPG mocks base method.
func (m *MockSecurityKey) StringsGPG(arg0, arg1 string) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StringsGPG", arg0, arg1)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StringsGPG indicates an expected call of StringsGPG.
func (mr *MockSecurityKeyMockRecorder) StringsGPG(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StringsGPG", reflect.TypeOf((*MockSecurityKey)(nil).StringsGPG), arg0, arg1)
}

// StringsSSH mocks base method.
func (m *MockSecurityKey) StringsSSH() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StringsSSH")
	ret0, _ := ret[0].([]string)
	return ret0
}

// StringsSSH indicates an expected call of StringsSSH.
func (mr *MockSecurityKeyMockRecorder) StringsSSH() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StringsSSH", reflect.TypeOf((*MockSecurityKey)(nil).StringsSSH))
}
