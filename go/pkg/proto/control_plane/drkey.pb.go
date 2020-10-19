// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.22.0
// 	protoc        v3.11.4
// source: proto/control_plane/v1/drkey.proto

package control_plane

import (
	context "context"
	proto "github.com/golang/protobuf/proto"
	drkey "github.com/scionproto/scion/go/pkg/proto/drkey"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

var File_proto_control_plane_v1_drkey_proto protoreflect.FileDescriptor

var file_proto_control_plane_v1_drkey_proto_rawDesc = []byte{
	0x0a, 0x22, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f,
	0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x64, 0x72, 0x6b, 0x65, 0x79, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x16, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x1e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2f, 0x64, 0x72, 0x6b, 0x65, 0x79, 0x2f, 0x6d, 0x67, 0x6d, 0x74, 0x2f, 0x76,
	0x31, 0x2f, 0x6d, 0x67, 0x6d, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x32, 0x70, 0x0a, 0x10,
	0x44, 0x52, 0x4b, 0x65, 0x79, 0x4c, 0x76, 0x6c, 0x31, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x12, 0x5c, 0x0a, 0x09, 0x44, 0x52, 0x4b, 0x65, 0x79, 0x4c, 0x76, 0x6c, 0x31, 0x12, 0x25, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x64, 0x72, 0x6b, 0x65, 0x79, 0x2e, 0x6d, 0x67, 0x6d, 0x74,
	0x2e, 0x76, 0x31, 0x2e, 0x44, 0x52, 0x4b, 0x65, 0x79, 0x4c, 0x76, 0x6c, 0x31, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x26, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x64, 0x72, 0x6b,
	0x65, 0x79, 0x2e, 0x6d, 0x67, 0x6d, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x52, 0x4b, 0x65, 0x79,
	0x4c, 0x76, 0x6c, 0x31, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x32, 0x70,
	0x0a, 0x10, 0x44, 0x52, 0x4b, 0x65, 0x79, 0x4c, 0x76, 0x6c, 0x32, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x12, 0x5c, 0x0a, 0x09, 0x44, 0x52, 0x4b, 0x65, 0x79, 0x4c, 0x76, 0x6c, 0x32, 0x12,
	0x25, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x64, 0x72, 0x6b, 0x65, 0x79, 0x2e, 0x6d, 0x67,
	0x6d, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x52, 0x4b, 0x65, 0x79, 0x4c, 0x76, 0x6c, 0x32, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x26, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x64,
	0x72, 0x6b, 0x65, 0x79, 0x2e, 0x6d, 0x67, 0x6d, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x52, 0x4b,
	0x65, 0x79, 0x4c, 0x76, 0x6c, 0x32, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00,
	0x42, 0x38, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73,
	0x63, 0x69, 0x6f, 0x6e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x63, 0x69, 0x6f, 0x6e, 0x2f,
	0x67, 0x6f, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var file_proto_control_plane_v1_drkey_proto_goTypes = []interface{}{
	(*drkey.DRKeyLvl1Request)(nil),  // 0: proto.drkey.mgmt.v1.DRKeyLvl1Request
	(*drkey.DRKeyLvl2Request)(nil),  // 1: proto.drkey.mgmt.v1.DRKeyLvl2Request
	(*drkey.DRKeyLvl1Response)(nil), // 2: proto.drkey.mgmt.v1.DRKeyLvl1Response
	(*drkey.DRKeyLvl2Response)(nil), // 3: proto.drkey.mgmt.v1.DRKeyLvl2Response
}
var file_proto_control_plane_v1_drkey_proto_depIdxs = []int32{
	0, // 0: proto.control_plane.v1.DRKeyLvl1Service.DRKeyLvl1:input_type -> proto.drkey.mgmt.v1.DRKeyLvl1Request
	1, // 1: proto.control_plane.v1.DRKeyLvl2Service.DRKeyLvl2:input_type -> proto.drkey.mgmt.v1.DRKeyLvl2Request
	2, // 2: proto.control_plane.v1.DRKeyLvl1Service.DRKeyLvl1:output_type -> proto.drkey.mgmt.v1.DRKeyLvl1Response
	3, // 3: proto.control_plane.v1.DRKeyLvl2Service.DRKeyLvl2:output_type -> proto.drkey.mgmt.v1.DRKeyLvl2Response
	2, // [2:4] is the sub-list for method output_type
	0, // [0:2] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_proto_control_plane_v1_drkey_proto_init() }
func file_proto_control_plane_v1_drkey_proto_init() {
	if File_proto_control_plane_v1_drkey_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_control_plane_v1_drkey_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   2,
		},
		GoTypes:           file_proto_control_plane_v1_drkey_proto_goTypes,
		DependencyIndexes: file_proto_control_plane_v1_drkey_proto_depIdxs,
	}.Build()
	File_proto_control_plane_v1_drkey_proto = out.File
	file_proto_control_plane_v1_drkey_proto_rawDesc = nil
	file_proto_control_plane_v1_drkey_proto_goTypes = nil
	file_proto_control_plane_v1_drkey_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// DRKeyLvl1ServiceClient is the client API for DRKeyLvl1Service service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type DRKeyLvl1ServiceClient interface {
	DRKeyLvl1(ctx context.Context, in *drkey.DRKeyLvl1Request, opts ...grpc.CallOption) (*drkey.DRKeyLvl1Response, error)
}

type dRKeyLvl1ServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewDRKeyLvl1ServiceClient(cc grpc.ClientConnInterface) DRKeyLvl1ServiceClient {
	return &dRKeyLvl1ServiceClient{cc}
}

func (c *dRKeyLvl1ServiceClient) DRKeyLvl1(ctx context.Context, in *drkey.DRKeyLvl1Request, opts ...grpc.CallOption) (*drkey.DRKeyLvl1Response, error) {
	out := new(drkey.DRKeyLvl1Response)
	err := c.cc.Invoke(ctx, "/proto.control_plane.v1.DRKeyLvl1Service/DRKeyLvl1", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DRKeyLvl1ServiceServer is the server API for DRKeyLvl1Service service.
type DRKeyLvl1ServiceServer interface {
	DRKeyLvl1(context.Context, *drkey.DRKeyLvl1Request) (*drkey.DRKeyLvl1Response, error)
}

// UnimplementedDRKeyLvl1ServiceServer can be embedded to have forward compatible implementations.
type UnimplementedDRKeyLvl1ServiceServer struct {
}

func (*UnimplementedDRKeyLvl1ServiceServer) DRKeyLvl1(context.Context, *drkey.DRKeyLvl1Request) (*drkey.DRKeyLvl1Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DRKeyLvl1 not implemented")
}

func RegisterDRKeyLvl1ServiceServer(s *grpc.Server, srv DRKeyLvl1ServiceServer) {
	s.RegisterService(&_DRKeyLvl1Service_serviceDesc, srv)
}

func _DRKeyLvl1Service_DRKeyLvl1_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(drkey.DRKeyLvl1Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DRKeyLvl1ServiceServer).DRKeyLvl1(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.control_plane.v1.DRKeyLvl1Service/DRKeyLvl1",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DRKeyLvl1ServiceServer).DRKeyLvl1(ctx, req.(*drkey.DRKeyLvl1Request))
	}
	return interceptor(ctx, in, info, handler)
}

var _DRKeyLvl1Service_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.control_plane.v1.DRKeyLvl1Service",
	HandlerType: (*DRKeyLvl1ServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "DRKeyLvl1",
			Handler:    _DRKeyLvl1Service_DRKeyLvl1_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/control_plane/v1/drkey.proto",
}

// DRKeyLvl2ServiceClient is the client API for DRKeyLvl2Service service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type DRKeyLvl2ServiceClient interface {
	DRKeyLvl2(ctx context.Context, in *drkey.DRKeyLvl2Request, opts ...grpc.CallOption) (*drkey.DRKeyLvl2Response, error)
}

type dRKeyLvl2ServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewDRKeyLvl2ServiceClient(cc grpc.ClientConnInterface) DRKeyLvl2ServiceClient {
	return &dRKeyLvl2ServiceClient{cc}
}

func (c *dRKeyLvl2ServiceClient) DRKeyLvl2(ctx context.Context, in *drkey.DRKeyLvl2Request, opts ...grpc.CallOption) (*drkey.DRKeyLvl2Response, error) {
	out := new(drkey.DRKeyLvl2Response)
	err := c.cc.Invoke(ctx, "/proto.control_plane.v1.DRKeyLvl2Service/DRKeyLvl2", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DRKeyLvl2ServiceServer is the server API for DRKeyLvl2Service service.
type DRKeyLvl2ServiceServer interface {
	DRKeyLvl2(context.Context, *drkey.DRKeyLvl2Request) (*drkey.DRKeyLvl2Response, error)
}

// UnimplementedDRKeyLvl2ServiceServer can be embedded to have forward compatible implementations.
type UnimplementedDRKeyLvl2ServiceServer struct {
}

func (*UnimplementedDRKeyLvl2ServiceServer) DRKeyLvl2(context.Context, *drkey.DRKeyLvl2Request) (*drkey.DRKeyLvl2Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DRKeyLvl2 not implemented")
}

func RegisterDRKeyLvl2ServiceServer(s *grpc.Server, srv DRKeyLvl2ServiceServer) {
	s.RegisterService(&_DRKeyLvl2Service_serviceDesc, srv)
}

func _DRKeyLvl2Service_DRKeyLvl2_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(drkey.DRKeyLvl2Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DRKeyLvl2ServiceServer).DRKeyLvl2(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.control_plane.v1.DRKeyLvl2Service/DRKeyLvl2",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DRKeyLvl2ServiceServer).DRKeyLvl2(ctx, req.(*drkey.DRKeyLvl2Request))
	}
	return interceptor(ctx, in, info, handler)
}

var _DRKeyLvl2Service_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.control_plane.v1.DRKeyLvl2Service",
	HandlerType: (*DRKeyLvl2ServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "DRKeyLvl2",
			Handler:    _DRKeyLvl2Service_DRKeyLvl2_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/control_plane/v1/drkey.proto",
}
