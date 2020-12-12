// Code generated by protoc-gen-go. DO NOT EDIT.
// source: rpc/scanner/service.proto

package scanner

import (
	fmt "fmt"
	common "github.com/AlaskaAirlines/trivy/rpc/common"
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

type ScanRequest struct {
	Target               string       `protobuf:"bytes,1,opt,name=target,proto3" json:"target,omitempty"`
	ArtifactId           string       `protobuf:"bytes,2,opt,name=artifact_id,json=artifactId,proto3" json:"artifact_id,omitempty"`
	BlobIds              []string     `protobuf:"bytes,3,rep,name=blob_ids,json=blobIds,proto3" json:"blob_ids,omitempty"`
	Options              *ScanOptions `protobuf:"bytes,4,opt,name=options,proto3" json:"options,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *ScanRequest) Reset()         { *m = ScanRequest{} }
func (m *ScanRequest) String() string { return proto.CompactTextString(m) }
func (*ScanRequest) ProtoMessage()    {}
func (*ScanRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_60d0e837512b18d4, []int{0}
}

func (m *ScanRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ScanRequest.Unmarshal(m, b)
}
func (m *ScanRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ScanRequest.Marshal(b, m, deterministic)
}
func (m *ScanRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ScanRequest.Merge(m, src)
}
func (m *ScanRequest) XXX_Size() int {
	return xxx_messageInfo_ScanRequest.Size(m)
}
func (m *ScanRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ScanRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ScanRequest proto.InternalMessageInfo

func (m *ScanRequest) GetTarget() string {
	if m != nil {
		return m.Target
	}
	return ""
}

func (m *ScanRequest) GetArtifactId() string {
	if m != nil {
		return m.ArtifactId
	}
	return ""
}

func (m *ScanRequest) GetBlobIds() []string {
	if m != nil {
		return m.BlobIds
	}
	return nil
}

func (m *ScanRequest) GetOptions() *ScanOptions {
	if m != nil {
		return m.Options
	}
	return nil
}

type ScanOptions struct {
	VulnType             []string `protobuf:"bytes,1,rep,name=vuln_type,json=vulnType,proto3" json:"vuln_type,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ScanOptions) Reset()         { *m = ScanOptions{} }
func (m *ScanOptions) String() string { return proto.CompactTextString(m) }
func (*ScanOptions) ProtoMessage()    {}
func (*ScanOptions) Descriptor() ([]byte, []int) {
	return fileDescriptor_60d0e837512b18d4, []int{1}
}

func (m *ScanOptions) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ScanOptions.Unmarshal(m, b)
}
func (m *ScanOptions) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ScanOptions.Marshal(b, m, deterministic)
}
func (m *ScanOptions) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ScanOptions.Merge(m, src)
}
func (m *ScanOptions) XXX_Size() int {
	return xxx_messageInfo_ScanOptions.Size(m)
}
func (m *ScanOptions) XXX_DiscardUnknown() {
	xxx_messageInfo_ScanOptions.DiscardUnknown(m)
}

var xxx_messageInfo_ScanOptions proto.InternalMessageInfo

func (m *ScanOptions) GetVulnType() []string {
	if m != nil {
		return m.VulnType
	}
	return nil
}

type ScanResponse struct {
	Os                   *common.OS `protobuf:"bytes,1,opt,name=os,proto3" json:"os,omitempty"`
	Eosl                 bool       `protobuf:"varint,2,opt,name=eosl,proto3" json:"eosl,omitempty"`
	Results              []*Result  `protobuf:"bytes,3,rep,name=results,proto3" json:"results,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *ScanResponse) Reset()         { *m = ScanResponse{} }
func (m *ScanResponse) String() string { return proto.CompactTextString(m) }
func (*ScanResponse) ProtoMessage()    {}
func (*ScanResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_60d0e837512b18d4, []int{2}
}

func (m *ScanResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ScanResponse.Unmarshal(m, b)
}
func (m *ScanResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ScanResponse.Marshal(b, m, deterministic)
}
func (m *ScanResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ScanResponse.Merge(m, src)
}
func (m *ScanResponse) XXX_Size() int {
	return xxx_messageInfo_ScanResponse.Size(m)
}
func (m *ScanResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ScanResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ScanResponse proto.InternalMessageInfo

func (m *ScanResponse) GetOs() *common.OS {
	if m != nil {
		return m.Os
	}
	return nil
}

func (m *ScanResponse) GetEosl() bool {
	if m != nil {
		return m.Eosl
	}
	return false
}

func (m *ScanResponse) GetResults() []*Result {
	if m != nil {
		return m.Results
	}
	return nil
}

// Result is the same as github.com/AlaskaAirlines/trivy/pkg/report.Result
type Result struct {
	Target               string                  `protobuf:"bytes,1,opt,name=target,proto3" json:"target,omitempty"`
	Vulnerabilities      []*common.Vulnerability `protobuf:"bytes,2,rep,name=vulnerabilities,proto3" json:"vulnerabilities,omitempty"`
	Type                 string                  `protobuf:"bytes,3,opt,name=type,proto3" json:"type,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                `json:"-"`
	XXX_unrecognized     []byte                  `json:"-"`
	XXX_sizecache        int32                   `json:"-"`
}

func (m *Result) Reset()         { *m = Result{} }
func (m *Result) String() string { return proto.CompactTextString(m) }
func (*Result) ProtoMessage()    {}
func (*Result) Descriptor() ([]byte, []int) {
	return fileDescriptor_60d0e837512b18d4, []int{3}
}

func (m *Result) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Result.Unmarshal(m, b)
}
func (m *Result) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Result.Marshal(b, m, deterministic)
}
func (m *Result) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Result.Merge(m, src)
}
func (m *Result) XXX_Size() int {
	return xxx_messageInfo_Result.Size(m)
}
func (m *Result) XXX_DiscardUnknown() {
	xxx_messageInfo_Result.DiscardUnknown(m)
}

var xxx_messageInfo_Result proto.InternalMessageInfo

func (m *Result) GetTarget() string {
	if m != nil {
		return m.Target
	}
	return ""
}

func (m *Result) GetVulnerabilities() []*common.Vulnerability {
	if m != nil {
		return m.Vulnerabilities
	}
	return nil
}

func (m *Result) GetType() string {
	if m != nil {
		return m.Type
	}
	return ""
}

func init() {
	proto.RegisterType((*ScanRequest)(nil), "trivy.scanner.v1.ScanRequest")
	proto.RegisterType((*ScanOptions)(nil), "trivy.scanner.v1.ScanOptions")
	proto.RegisterType((*ScanResponse)(nil), "trivy.scanner.v1.ScanResponse")
	proto.RegisterType((*Result)(nil), "trivy.scanner.v1.Result")
}

func init() { proto.RegisterFile("rpc/scanner/service.proto", fileDescriptor_60d0e837512b18d4) }

var fileDescriptor_60d0e837512b18d4 = []byte{
	// 377 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x92, 0xc1, 0x6b, 0xdb, 0x30,
	0x14, 0xc6, 0xb1, 0x13, 0xe2, 0xf8, 0x79, 0xb0, 0xa0, 0xc3, 0x70, 0x12, 0xb6, 0x19, 0x9f, 0xc2,
	0x0e, 0x36, 0xf3, 0x60, 0xbb, 0x0f, 0x72, 0xc8, 0x29, 0x45, 0x29, 0x3d, 0xf4, 0x12, 0x64, 0x59,
	0x4d, 0x05, 0x8e, 0xe5, 0x48, 0xb2, 0xa9, 0xe9, 0x7f, 0xd2, 0xbf, 0xb6, 0x58, 0x72, 0xa0, 0x49,
	0xc9, 0xed, 0xe9, 0xbd, 0xcf, 0x4f, 0xbf, 0xef, 0xb3, 0x60, 0x2e, 0x6b, 0x9a, 0x2a, 0x4a, 0xaa,
	0x8a, 0xc9, 0x54, 0x31, 0xd9, 0x72, 0xca, 0x92, 0x5a, 0x0a, 0x2d, 0xd0, 0x4c, 0x4b, 0xde, 0x76,
	0xc9, 0x30, 0x4c, 0xda, 0xdf, 0x8b, 0xbf, 0x07, 0xae, 0x9f, 0x9b, 0x3c, 0xa1, 0xe2, 0x98, 0x92,
	0x53, 0x43, 0x14, 0xa3, 0x8d, 0xe4, 0xba, 0x4b, 0x8d, 0x32, 0xed, 0x57, 0x51, 0x71, 0x3c, 0x8a,
	0xea, 0x72, 0x53, 0xfc, 0xe6, 0x40, 0xb0, 0xa3, 0xa4, 0xc2, 0xec, 0xd4, 0x30, 0xa5, 0xd1, 0x37,
	0x98, 0x68, 0x22, 0x0f, 0x4c, 0x87, 0x4e, 0xe4, 0xac, 0x7c, 0x3c, 0x9c, 0xd0, 0x4f, 0x08, 0x88,
	0xd4, 0xfc, 0x89, 0x50, 0xbd, 0xe7, 0x45, 0xe8, 0x9a, 0x21, 0x9c, 0x5b, 0x9b, 0x02, 0xcd, 0x61,
	0x9a, 0x97, 0x22, 0xdf, 0xf3, 0x42, 0x85, 0xa3, 0x68, 0xb4, 0xf2, 0xb1, 0xd7, 0x9f, 0x37, 0x85,
	0x42, 0xff, 0xc0, 0x13, 0xb5, 0xe6, 0xa2, 0x52, 0xe1, 0x38, 0x72, 0x56, 0x41, 0xf6, 0x3d, 0xb9,
	0xe6, 0x4f, 0x7a, 0x86, 0xad, 0x15, 0xe1, 0xb3, 0x3a, 0xfe, 0x65, 0xd9, 0x86, 0x3e, 0x5a, 0x82,
	0xdf, 0x36, 0x65, 0xb5, 0xd7, 0x5d, 0xcd, 0x42, 0xc7, 0xdc, 0x31, 0xed, 0x1b, 0xf7, 0x5d, 0xcd,
	0xe2, 0x17, 0xf8, 0x62, 0x7d, 0xa8, 0x5a, 0x54, 0x8a, 0xa1, 0x08, 0x5c, 0xa1, 0x8c, 0x89, 0x20,
	0x9b, 0x0d, 0xf7, 0xd9, 0x04, 0x92, 0xed, 0x0e, 0xbb, 0x42, 0x21, 0x04, 0x63, 0x26, 0x54, 0x69,
	0xbc, 0x4c, 0xb1, 0xa9, 0x51, 0x06, 0x9e, 0x64, 0xaa, 0x29, 0xb5, 0x35, 0x11, 0x64, 0xe1, 0x67,
	0x54, 0x6c, 0x04, 0xf8, 0x2c, 0x8c, 0x5f, 0x61, 0x62, 0x5b, 0x37, 0xc3, 0x5b, 0xc3, 0xd7, 0x9e,
	0x93, 0x49, 0x92, 0xf3, 0x92, 0x6b, 0xce, 0x54, 0xe8, 0x9a, 0xed, 0xcb, 0x4b, 0xb0, 0x87, 0x0f,
	0xa2, 0x0e, 0x5f, 0x7f, 0xd3, 0x03, 0x1b, 0xeb, 0x23, 0xb3, 0xdc, 0xd4, 0xd9, 0x1d, 0x78, 0x3b,
	0x8b, 0x86, 0xd6, 0x30, 0xee, 0x4b, 0x74, 0x23, 0xdd, 0xe1, 0x0f, 0x2f, 0x7e, 0xdc, 0x1a, 0xdb,
	0xe0, 0xfe, 0xfb, 0x8f, 0xde, 0x30, 0xca, 0x27, 0xe6, 0x8d, 0xfc, 0x79, 0x0f, 0x00, 0x00, 0xff,
	0xff, 0xdf, 0x43, 0x89, 0x65, 0x8a, 0x02, 0x00, 0x00,
}
