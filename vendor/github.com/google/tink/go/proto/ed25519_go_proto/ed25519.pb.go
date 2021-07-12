// Copyright 2020 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: third_party/tink/proto/ed25519.proto

package ed25519_go_proto

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Ed25519KeyFormat struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Ed25519KeyFormat) Reset()         { *m = Ed25519KeyFormat{} }
func (m *Ed25519KeyFormat) String() string { return proto.CompactTextString(m) }
func (*Ed25519KeyFormat) ProtoMessage()    {}
func (*Ed25519KeyFormat) Descriptor() ([]byte, []int) {
	return fileDescriptor_677c38422e9f421e, []int{0}
}

func (m *Ed25519KeyFormat) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Ed25519KeyFormat.Unmarshal(m, b)
}
func (m *Ed25519KeyFormat) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Ed25519KeyFormat.Marshal(b, m, deterministic)
}
func (m *Ed25519KeyFormat) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Ed25519KeyFormat.Merge(m, src)
}
func (m *Ed25519KeyFormat) XXX_Size() int {
	return xxx_messageInfo_Ed25519KeyFormat.Size(m)
}
func (m *Ed25519KeyFormat) XXX_DiscardUnknown() {
	xxx_messageInfo_Ed25519KeyFormat.DiscardUnknown(m)
}

var xxx_messageInfo_Ed25519KeyFormat proto.InternalMessageInfo

// key_type: type.googleapis.com/google.crypto.tink.Ed25519PublicKey
type Ed25519PublicKey struct {
	// Required.
	Version uint32 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	// The public key is 32 bytes, encoded according to
	// https://tools.ietf.org/html/rfc8032#section-5.1.2.
	// Required.
	KeyValue             []byte   `protobuf:"bytes,2,opt,name=key_value,json=keyValue,proto3" json:"key_value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Ed25519PublicKey) Reset()         { *m = Ed25519PublicKey{} }
func (m *Ed25519PublicKey) String() string { return proto.CompactTextString(m) }
func (*Ed25519PublicKey) ProtoMessage()    {}
func (*Ed25519PublicKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_677c38422e9f421e, []int{1}
}

func (m *Ed25519PublicKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Ed25519PublicKey.Unmarshal(m, b)
}
func (m *Ed25519PublicKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Ed25519PublicKey.Marshal(b, m, deterministic)
}
func (m *Ed25519PublicKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Ed25519PublicKey.Merge(m, src)
}
func (m *Ed25519PublicKey) XXX_Size() int {
	return xxx_messageInfo_Ed25519PublicKey.Size(m)
}
func (m *Ed25519PublicKey) XXX_DiscardUnknown() {
	xxx_messageInfo_Ed25519PublicKey.DiscardUnknown(m)
}

var xxx_messageInfo_Ed25519PublicKey proto.InternalMessageInfo

func (m *Ed25519PublicKey) GetVersion() uint32 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *Ed25519PublicKey) GetKeyValue() []byte {
	if m != nil {
		return m.KeyValue
	}
	return nil
}

// key_type: type.googleapis.com/google.crypto.tink.Ed25519PrivateKey
type Ed25519PrivateKey struct {
	// Required.
	Version uint32 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	// The private key is 32 bytes of cryptographically secure random data.
	// See https://tools.ietf.org/html/rfc8032#section-5.1.5.
	// Required.
	KeyValue []byte `protobuf:"bytes,2,opt,name=key_value,json=keyValue,proto3" json:"key_value,omitempty"`
	// The corresponding public key.
	PublicKey            *Ed25519PublicKey `protobuf:"bytes,3,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Ed25519PrivateKey) Reset()         { *m = Ed25519PrivateKey{} }
func (m *Ed25519PrivateKey) String() string { return proto.CompactTextString(m) }
func (*Ed25519PrivateKey) ProtoMessage()    {}
func (*Ed25519PrivateKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_677c38422e9f421e, []int{2}
}

func (m *Ed25519PrivateKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Ed25519PrivateKey.Unmarshal(m, b)
}
func (m *Ed25519PrivateKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Ed25519PrivateKey.Marshal(b, m, deterministic)
}
func (m *Ed25519PrivateKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Ed25519PrivateKey.Merge(m, src)
}
func (m *Ed25519PrivateKey) XXX_Size() int {
	return xxx_messageInfo_Ed25519PrivateKey.Size(m)
}
func (m *Ed25519PrivateKey) XXX_DiscardUnknown() {
	xxx_messageInfo_Ed25519PrivateKey.DiscardUnknown(m)
}

var xxx_messageInfo_Ed25519PrivateKey proto.InternalMessageInfo

func (m *Ed25519PrivateKey) GetVersion() uint32 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *Ed25519PrivateKey) GetKeyValue() []byte {
	if m != nil {
		return m.KeyValue
	}
	return nil
}

func (m *Ed25519PrivateKey) GetPublicKey() *Ed25519PublicKey {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

func init() {
	proto.RegisterType((*Ed25519KeyFormat)(nil), "google.crypto.tink.Ed25519KeyFormat")
	proto.RegisterType((*Ed25519PublicKey)(nil), "google.crypto.tink.Ed25519PublicKey")
	proto.RegisterType((*Ed25519PrivateKey)(nil), "google.crypto.tink.Ed25519PrivateKey")
}

func init() {
	proto.RegisterFile("proto/ed25519.proto", fileDescriptor_677c38422e9f421e)
}

var fileDescriptor_677c38422e9f421e = []byte{
	// 250 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x52, 0x29, 0xc9, 0xc8, 0x2c,
	0x4a, 0x89, 0x2f, 0x48, 0x2c, 0x2a, 0xa9, 0xd4, 0x2f, 0xc9, 0xcc, 0xcb, 0xd6, 0x2f, 0x28, 0xca,
	0x2f, 0xc9, 0xd7, 0x4f, 0x4d, 0x31, 0x32, 0x35, 0x35, 0xb4, 0xd4, 0x03, 0xf3, 0x84, 0x84, 0xd2,
	0xf3, 0xf3, 0xd3, 0x73, 0x52, 0xf5, 0x92, 0x8b, 0x2a, 0x0b, 0x4a, 0xf2, 0xf5, 0x40, 0xea, 0x94,
	0x84, 0xb8, 0x04, 0x5c, 0x21, 0x8a, 0xbc, 0x53, 0x2b, 0xdd, 0xf2, 0x8b, 0x72, 0x13, 0x4b, 0x94,
	0x3c, 0xe1, 0x62, 0x01, 0xa5, 0x49, 0x39, 0x99, 0xc9, 0xde, 0xa9, 0x95, 0x42, 0x12, 0x5c, 0xec,
	0x65, 0xa9, 0x45, 0xc5, 0x99, 0xf9, 0x79, 0x12, 0x8c, 0x0a, 0x8c, 0x1a, 0xbc, 0x41, 0x30, 0xae,
	0x90, 0x34, 0x17, 0x67, 0x76, 0x6a, 0x65, 0x7c, 0x59, 0x62, 0x4e, 0x69, 0xaa, 0x04, 0x93, 0x02,
	0xa3, 0x06, 0x4f, 0x10, 0x47, 0x76, 0x6a, 0x65, 0x18, 0x88, 0xaf, 0xd4, 0xcf, 0xc8, 0x25, 0x08,
	0x33, 0xab, 0x28, 0xb3, 0x2c, 0xb1, 0x24, 0x95, 0x7c, 0xc3, 0x84, 0x9c, 0xb9, 0xb8, 0x0a, 0xc0,
	0x0e, 0x8a, 0xcf, 0x4e, 0xad, 0x94, 0x60, 0x56, 0x60, 0xd4, 0xe0, 0x36, 0x52, 0xd1, 0xc3, 0xf4,
	0x94, 0x1e, 0xba, 0xeb, 0x83, 0x38, 0x0b, 0x60, 0x4c, 0xa7, 0x08, 0x2e, 0x99, 0xe4, 0xfc, 0x5c,
	0x6c, 0xba, 0xc0, 0x81, 0x14, 0xc0, 0x18, 0xa5, 0x9b, 0x9e, 0x59, 0x92, 0x51, 0x9a, 0xa4, 0x97,
	0x9c, 0x9f, 0xab, 0x0f, 0x51, 0x86, 0x25, 0x48, 0xe3, 0xd3, 0xf3, 0xe3, 0xc1, 0x02, 0x8b, 0x98,
	0xd8, 0x42, 0x3c, 0xfd, 0xbc, 0x03, 0x9c, 0x92, 0xd8, 0xc0, 0x7c, 0x63, 0x40, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xe2, 0x32, 0x0c, 0x2b, 0x8d, 0x01, 0x00, 0x00,
}
