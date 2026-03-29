package server

import (
	"context"
	"io"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
)

// FakeAttestStream simulates the gRPC bidirectional streaming interface for
// testing the Attest method.
type FakeAttestStream struct {
	nodeattestorv1.NodeAttestor_AttestServer
	Requests  []*nodeattestorv1.AttestRequest
	Responses []*nodeattestorv1.AttestResponse
	recvIdx   int
}

func (s *FakeAttestStream) Recv() (*nodeattestorv1.AttestRequest, error) {
	if s.recvIdx >= len(s.Requests) {
		return nil, io.EOF
	}
	req := s.Requests[s.recvIdx]
	s.recvIdx++
	return req, nil
}

func (s *FakeAttestStream) Send(resp *nodeattestorv1.AttestResponse) error {
	s.Responses = append(s.Responses, resp)
	return nil
}

func (s *FakeAttestStream) Context() context.Context {
	return context.Background()
}
