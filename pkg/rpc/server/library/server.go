package library

import (
	"context"
	"time"

	"github.com/google/wire"
	"golang.org/x/xerrors"

	detector "github.com/AlaskaAirlines/trivy/pkg/detector/library"
	"github.com/AlaskaAirlines/trivy/pkg/log"
	"github.com/AlaskaAirlines/trivy/pkg/rpc"
	"github.com/AlaskaAirlines/trivy/pkg/vulnerability"
	proto "github.com/AlaskaAirlines/trivy/rpc/detector"
)

// SuperSet binds the dependencies for library RPC server
var SuperSet = wire.NewSet(
	detector.SuperSet,
	vulnerability.SuperSet,
	NewServer,
)

// Server is for backward compatibility
type Server struct {
	detector   detector.Operation
	vulnClient vulnerability.Operation
}

// NewServer is the facotry method for Server
func NewServer(detector detector.Operation, vulnClient vulnerability.Operation) *Server {
	return &Server{detector: detector, vulnClient: vulnClient}
}

// Detect is for backward compatibility
func (s *Server) Detect(_ context.Context, req *proto.LibDetectRequest) (res *proto.DetectResponse, err error) {
	vulns, err := s.detector.Detect("", req.FilePath, time.Time{}, rpc.ConvertFromRPCLibraries(req.Libraries))
	if err != nil {
		err = xerrors.Errorf("failed to detect library vulnerabilities: %w", err)
		log.Logger.Error(err)
		return nil, err
	}

	s.vulnClient.FillInfo(vulns, "")

	return &proto.DetectResponse{Vulnerabilities: rpc.ConvertToRPCVulns(vulns)}, nil
}
