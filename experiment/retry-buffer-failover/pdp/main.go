// Command pdp is a routing policy decision point served over Envoy's ext_proc API.
//
// On request headers it chooses the order of the priority groups for the request and returns it
// as dynamic metadata under envoy.ai.routing, which the priority_group cluster specifier reads
// once the route cache is cleared. The order comes from the x-pdp-order request header when
// present (a comma-separated list of group names), then from the model the AI protocol manager
// parsed out of the request, otherwise the default order below.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

var defaultOrder = []string{"gemini", "vertex"}

// rewrittenBody replaces the request body when the request carries x-pdp-rewrite-body, the way a
// PDP that rewrites the prompt or the model would. e2e.py checks every attempt receives it.
const rewrittenBody = `{"contents":[{"role":"user","parts":[{"text":"rewritten by the routing PDP"}]}]}`

type server struct {
	extprocv3.UnimplementedExternalProcessorServer
}

func headerValue(headers *corev3.HeaderMap, name string) string {
	for _, h := range headers.GetHeaders() {
		if strings.EqualFold(h.GetKey(), name) {
			if v := h.GetValue(); v != "" {
				return v
			}
			return string(h.GetRawValue())
		}
	}
	return ""
}

// modelOrder routes by the model the AI protocol manager parsed out of the request.
var modelOrder = map[string][]string{
	"gemini-2.5-pro": {"vertex", "gemini"},
}

func parsedModel(req *extprocv3.ProcessingRequest) string {
	attrs := req.GetAttributes()["envoy.filters.http.ext_proc"]
	if attrs == nil {
		return ""
	}
	return attrs.GetFields()["filter_state['envoy.ai.model.request']"].GetStringValue()
}

func decide(headers *corev3.HeaderMap, model string) []string {
	if v := headerValue(headers, "x-pdp-order"); v != "" {
		var order []string
		for _, g := range strings.Split(v, ",") {
			if g = strings.TrimSpace(g); g != "" {
				order = append(order, g)
			}
		}
		if len(order) > 0 {
			return order
		}
	}
	if order, ok := modelOrder[model]; ok {
		return order
	}
	return defaultOrder
}

func routingMetadata(order []string) (*structpb.Struct, error) {
	groups := make([]any, 0, len(order))
	for _, g := range order {
		groups = append(groups, map[string]any{"name": g})
	}
	return structpb.NewStruct(map[string]any{
		"envoy.ai.routing": map[string]any{"priority_groups": groups},
	})
}

func (s *server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch v := req.Request.(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			headers := v.RequestHeaders.GetHeaders()
			model := parsedModel(req)
			order := decide(headers, model)
			md, err := routingMetadata(order)
			if err != nil {
				return err
			}
			rewrite := headerValue(headers, "x-pdp-rewrite-body") != ""
			log.Printf("pdp: path=%s model=%q order=%v rewrite=%v", headerValue(headers, ":path"),
				model, order, rewrite)
			common := &extprocv3.CommonResponse{
				ClearRouteCache: true,
				HeaderMutation: &extprocv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{{
						Header: &corev3.HeaderValue{
							Key:      "x-pdp-decision",
							RawValue: []byte(strings.Join(order, ",")),
						},
					}},
				},
			}
			if rewrite {
				common.Status = extprocv3.CommonResponse_CONTINUE_AND_REPLACE
				common.BodyMutation = &extprocv3.BodyMutation{
					Mutation: &extprocv3.BodyMutation_Body{Body: []byte(rewrittenBody)},
				}
			}
			resp := &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_RequestHeaders{
					RequestHeaders: &extprocv3.HeadersResponse{Response: common},
				},
				DynamicMetadata: md,
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		default:
			return fmt.Errorf("pdp: unexpected request %T; configure header-only processing", v)
		}
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18080", "listen address")
	flag.Parse()
	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	g := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(g, &server{})
	log.Printf("pdp: listening on %s", *addr)
	log.Fatal(g.Serve(lis))
}
