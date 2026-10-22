// An ext_proc server for the composite model `coding_model`: model routing and token management.
//
// Model routing: a request for `coding_model` goes to Claude on Vertex AI while the tenant has
// Claude budget left, and to Gemini on Vertex AI after that. The choice leaves as x-ai-backend-*
// request headers, which the gateway turns into the AI Protocol Manager's filter state keys.
//
// Token management: the tenant's spend is what the backend reported, read from the
// envoy.ai.token_usage record the AI Protocol Manager publishes and Envoy forwards on the response
// trailers.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	compositeModel = "coding_model"
	vertexPrefix   = "/v1/projects/acme/locations/us-east5/publishers"
)

type backend struct {
	api, model, binding string
}

var (
	claude = backend{
		api:   "ANTHROPIC_MESSAGES",
		model: "claude-sonnet-4-5@20250929",
		binding: `{"uri_pattern": "` + vertexPrefix + `/anthropic/models/{model}:{rawPredict|streamRawPredict}",` +
			` "mutations": [{"body_field": "model"},` +
			` {"body_field": "anthropic_version", "value": "vertex-2023-10-16", "keep_existing": true}]}`,
	}
	gemini = backend{
		api:     "GEMINI_GENERATE_CONTENT",
		model:   "gemini-2.5-flash",
		binding: vertexPrefix + "/google/models/{model}:{generateContent|streamGenerateContent?alt=sse}",
	}
)

type server struct {
	extprocv3.UnimplementedExternalProcessorServer
	claudeBudget uint64
	vertexHost   string

	mu    sync.Mutex
	spent map[string]uint64
}

func (s *server) pick(tenant string) backend {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.spent[tenant] < s.claudeBudget {
		return claude
	}
	return gemini
}

func (s *server) charge(tenant string, tokens uint64) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.spent[tenant] += tokens
	return s.spent[tenant]
}

func (s *server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	tenant := "anonymous"
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		resp := &extprocv3.ProcessingResponse{}
		switch r := req.Request.(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			for _, h := range r.RequestHeaders.GetHeaders().GetHeaders() {
				if h.Key == "x-tenant" {
					tenant = string(h.RawValue)
				}
			}
			resp.Response = &extprocv3.ProcessingResponse_RequestHeaders{
				RequestHeaders: &extprocv3.HeadersResponse{},
			}
		case *extprocv3.ProcessingRequest_RequestBody:
			resp.Response = &extprocv3.ProcessingResponse_RequestBody{
				RequestBody: &extprocv3.BodyResponse{Response: s.route(tenant, r.RequestBody.Body, req)},
			}
		case *extprocv3.ProcessingRequest_ResponseTrailers:
			s.account(tenant, req)
			resp.Response = &extprocv3.ProcessingResponse_ResponseTrailers{
				ResponseTrailers: &extprocv3.TrailersResponse{},
			}
		default:
			log.Printf("unexpected message %T", r)
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

func (s *server) route(tenant string, body []byte, req *extprocv3.ProcessingRequest) *extprocv3.CommonResponse {
	var request struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &request); err != nil || request.Model != compositeModel {
		log.Printf("route  tenant=%s model=%q: not %s, left alone", tenant, request.Model, compositeModel)
		return &extprocv3.CommonResponse{}
	}
	estimate := "?"
	if info, ok := req.GetMetadataContext().GetTypedFilterMetadata()["envoy.ai.request_info"]; ok {
		estimate = fmt.Sprint(uint64Field(info.Value, 7))
	}
	b := s.pick(tenant)
	log.Printf("route  tenant=%s model=%s estimated_input_tokens=%s -> %s %s", tenant,
		request.Model, estimate, b.api, b.model)
	return &extprocv3.CommonResponse{
		HeaderMutation: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
			header("x-ai-backend-api", b.api),
			header("x-ai-backend-binding", b.binding),
			header("x-ai-backend-model", b.model),
			header("x-ai-backend-host", s.vertexHost),
		}},
	}
}

func (s *server) account(tenant string, req *extprocv3.ProcessingRequest) {
	usage, ok := req.GetMetadataContext().GetTypedFilterMetadata()["envoy.ai.token_usage"]
	if !ok {
		log.Printf("usage  tenant=%s: no envoy.ai.token_usage on the trailers", tenant)
		return
	}
	total := uint64Field(usage.Value, 5)
	log.Printf("usage  tenant=%s model=%s input=%d output=%d total=%d -> tenant spent %d, Claude budget %d",
		tenant, stringField(usage.Value, 2), uint64Field(usage.Value, 3), uint64Field(usage.Value, 4),
		total, s.charge(tenant, total), s.claudeBudget)
}

func header(key, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: key, RawValue: []byte(value)},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}

// envoy.data.ai.v3 records are read off the wire, so this server needs no protos newer than
// go-control-plane's.
func field(msg []byte, want protowire.Number) []byte {
	for len(msg) > 0 {
		num, typ, n := protowire.ConsumeTag(msg)
		if n < 0 {
			return nil
		}
		msg = msg[n:]
		if typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(msg)
			if m < 0 {
				return nil
			}
			if num == want {
				return v
			}
			msg = msg[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, msg)
		if m < 0 {
			return nil
		}
		msg = msg[m:]
	}
	return nil
}

// A google.protobuf.UInt64Value field; 0 when absent.
func uint64Field(msg []byte, num protowire.Number) uint64 {
	wrapper := field(msg, num)
	n, typ, l := protowire.ConsumeTag(wrapper)
	if l < 0 || n != 1 || typ != protowire.VarintType {
		return 0
	}
	v, _ := protowire.ConsumeVarint(wrapper[l:])
	return v
}

func stringField(msg []byte, num protowire.Number) string { return string(field(msg, num)) }

func main() {
	addr := flag.String("addr", "127.0.0.1:50061", "listen address")
	budget := flag.Uint64("claude-budget", 50, "Claude tokens per tenant before routing to Gemini")
	host := flag.String("vertex-host", "us-east5-aiplatform.googleapis.com", "Vertex AI endpoint")
	flag.Parse()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	g := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(g, &server{
		claudeBudget: *budget, vertexHost: *host, spent: map[string]uint64{},
	})
	log.Printf("ext_proc on %s, Claude budget %d tokens per tenant", *addr, *budget)
	log.Fatal(g.Serve(lis))
}
