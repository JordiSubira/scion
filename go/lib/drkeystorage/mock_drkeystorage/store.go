// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/lib/drkeystorage (interfaces: SecretValueFactory,BaseStore,ServiceStore,ClientStore)

// Package mock_drkeystorage is a generated GoMock package.
package mock_drkeystorage

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	addr "github.com/scionproto/scion/go/lib/addr"
	drkey "github.com/scionproto/scion/go/lib/drkey"
	reflect "reflect"
	time "time"
)

// MockSecretValueFactory is a mock of SecretValueFactory interface
type MockSecretValueFactory struct {
	ctrl     *gomock.Controller
	recorder *MockSecretValueFactoryMockRecorder
}

// MockSecretValueFactoryMockRecorder is the mock recorder for MockSecretValueFactory
type MockSecretValueFactoryMockRecorder struct {
	mock *MockSecretValueFactory
}

// NewMockSecretValueFactory creates a new mock instance
func NewMockSecretValueFactory(ctrl *gomock.Controller) *MockSecretValueFactory {
	mock := &MockSecretValueFactory{ctrl: ctrl}
	mock.recorder = &MockSecretValueFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockSecretValueFactory) EXPECT() *MockSecretValueFactoryMockRecorder {
	return m.recorder
}

// GetSecretValue mocks base method
func (m *MockSecretValueFactory) GetSecretValue(arg0 time.Time) (drkey.SV, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSecretValue", arg0)
	ret0, _ := ret[0].(drkey.SV)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSecretValue indicates an expected call of GetSecretValue
func (mr *MockSecretValueFactoryMockRecorder) GetSecretValue(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSecretValue", reflect.TypeOf((*MockSecretValueFactory)(nil).GetSecretValue), arg0)
}

// MockBaseStore is a mock of BaseStore interface
type MockBaseStore struct {
	ctrl     *gomock.Controller
	recorder *MockBaseStoreMockRecorder
}

// MockBaseStoreMockRecorder is the mock recorder for MockBaseStore
type MockBaseStoreMockRecorder struct {
	mock *MockBaseStore
}

// NewMockBaseStore creates a new mock instance
func NewMockBaseStore(ctrl *gomock.Controller) *MockBaseStore {
	mock := &MockBaseStore{ctrl: ctrl}
	mock.recorder = &MockBaseStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockBaseStore) EXPECT() *MockBaseStoreMockRecorder {
	return m.recorder
}

// DeleteExpiredKeys mocks base method
func (m *MockBaseStore) DeleteExpiredKeys(arg0 context.Context) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteExpiredKeys", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteExpiredKeys indicates an expected call of DeleteExpiredKeys
func (mr *MockBaseStoreMockRecorder) DeleteExpiredKeys(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteExpiredKeys", reflect.TypeOf((*MockBaseStore)(nil).DeleteExpiredKeys), arg0)
}

// MockServiceStore is a mock of ServiceStore interface
type MockServiceStore struct {
	ctrl     *gomock.Controller
	recorder *MockServiceStoreMockRecorder
}

// MockServiceStoreMockRecorder is the mock recorder for MockServiceStore
type MockServiceStoreMockRecorder struct {
	mock *MockServiceStore
}

// NewMockServiceStore creates a new mock instance
func NewMockServiceStore(ctrl *gomock.Controller) *MockServiceStore {
	mock := &MockServiceStore{ctrl: ctrl}
	mock.recorder = &MockServiceStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockServiceStore) EXPECT() *MockServiceStoreMockRecorder {
	return m.recorder
}

// DeleteExpiredKeys mocks base method
func (m *MockServiceStore) DeleteExpiredKeys(arg0 context.Context) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteExpiredKeys", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteExpiredKeys indicates an expected call of DeleteExpiredKeys
func (mr *MockServiceStoreMockRecorder) DeleteExpiredKeys(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteExpiredKeys", reflect.TypeOf((*MockServiceStore)(nil).DeleteExpiredKeys), arg0)
}

// DeriveLvl1 mocks base method
func (m *MockServiceStore) DeriveLvl1(arg0 addr.IA, arg1 time.Time) (drkey.Lvl1Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeriveLvl1", arg0, arg1)
	ret0, _ := ret[0].(drkey.Lvl1Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeriveLvl1 indicates an expected call of DeriveLvl1
func (mr *MockServiceStoreMockRecorder) DeriveLvl1(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeriveLvl1", reflect.TypeOf((*MockServiceStore)(nil).DeriveLvl1), arg0, arg1)
}

// GetLvl1Key mocks base method
func (m *MockServiceStore) GetLvl1Key(arg0 context.Context, arg1 drkey.Lvl1Meta, arg2 time.Time) (drkey.Lvl1Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLvl1Key", arg0, arg1, arg2)
	ret0, _ := ret[0].(drkey.Lvl1Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLvl1Key indicates an expected call of GetLvl1Key
func (mr *MockServiceStoreMockRecorder) GetLvl1Key(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLvl1Key", reflect.TypeOf((*MockServiceStore)(nil).GetLvl1Key), arg0, arg1, arg2)
}

// KnownASes mocks base method
func (m *MockServiceStore) KnownASes(arg0 context.Context) ([]addr.IA, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "KnownASes", arg0)
	ret0, _ := ret[0].([]addr.IA)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// KnownASes indicates an expected call of KnownASes
func (mr *MockServiceStoreMockRecorder) KnownASes(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "KnownASes", reflect.TypeOf((*MockServiceStore)(nil).KnownASes), arg0)
}

// MockClientStore is a mock of ClientStore interface
type MockClientStore struct {
	ctrl     *gomock.Controller
	recorder *MockClientStoreMockRecorder
}

// MockClientStoreMockRecorder is the mock recorder for MockClientStore
type MockClientStoreMockRecorder struct {
	mock *MockClientStore
}

// NewMockClientStore creates a new mock instance
func NewMockClientStore(ctrl *gomock.Controller) *MockClientStore {
	mock := &MockClientStore{ctrl: ctrl}
	mock.recorder = &MockClientStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockClientStore) EXPECT() *MockClientStoreMockRecorder {
	return m.recorder
}

// DeleteExpiredKeys mocks base method
func (m *MockClientStore) DeleteExpiredKeys(arg0 context.Context) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteExpiredKeys", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteExpiredKeys indicates an expected call of DeleteExpiredKeys
func (mr *MockClientStoreMockRecorder) DeleteExpiredKeys(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteExpiredKeys", reflect.TypeOf((*MockClientStore)(nil).DeleteExpiredKeys), arg0)
}

// GetLvl2Key mocks base method
func (m *MockClientStore) GetLvl2Key(arg0 context.Context, arg1 drkey.Lvl2Meta, arg2 time.Time) (drkey.Lvl2Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLvl2Key", arg0, arg1, arg2)
	ret0, _ := ret[0].(drkey.Lvl2Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLvl2Key indicates an expected call of GetLvl2Key
func (mr *MockClientStoreMockRecorder) GetLvl2Key(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLvl2Key", reflect.TypeOf((*MockClientStore)(nil).GetLvl2Key), arg0, arg1, arg2)
}
