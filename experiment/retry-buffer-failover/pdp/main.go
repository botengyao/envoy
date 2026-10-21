// Command pdp is a routing policy decision point served over Envoy's ext_proc API.
//
// On request headers it chooses the priority groups for the request and returns them as dynamic
// metadata under envoy.ai.routing, which the priority_group cluster specifier reads once the route
// cache is cleared. The groups come from the x-pdp-groups request header when present (a JSON list
// of groups, each with optional clusters and weights), then from x-pdp-order (a comma-separated
// list of group names), then from the model the AI protocol manager parsed out of the request,
// otherwise the default order below.
//
// On x-pdp-rewrite-body it replaces the body with CONTINUE_AND_REPLACE. On x-test-mutate-body it
// switches the request body to BUFFERED and rewrites "hello" to "HELLO" in it, the way a filter
// between the AI protocol manager and the router may edit the body.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
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

// modelGroups gives whole groups for a model, so the policy can route through a group the route
// does not configure.
var modelGroups = map[string][]any{
	"gemini-2.5-flash-lite": {
		map[string]any{"name": "policy-vertex", "clusters": []any{
			map[string]any{"cluster_name": "vertex", "weight": 100},
		}},
		map[string]any{"name": "gemini"},
	},
}

func parsedModel(req *extprocv3.ProcessingRequest) string {
	attrs := req.GetAttributes()["envoy.filters.http.ext_proc"]
	if attrs == nil {
		return ""
	}
	return attrs.GetFields()["filter_state['envoy.ai.model.request']"].GetStringValue()
}

func decide(headers *corev3.HeaderMap, model string) ([]any, error) {
	if v := headerValue(headers, "x-pdp-groups"); v != "" {
		var groups []any
		if err := json.Unmarshal([]byte(v), &groups); err != nil {
			return nil, fmt.Errorf("pdp: x-pdp-groups: %w", err)
		}
		return groups, nil
	}
	var order []string
	for _, g := range strings.Split(headerValue(headers, "x-pdp-order"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			order = append(order, g)
		}
	}
	if len(order) > 0 {
		return named(order), nil
	}
	if groups, ok := modelGroups[model]; ok {
		return groups, nil
	}
	if order, ok := modelOrder[model]; ok {
		return named(order), nil
	}
	return named(defaultOrder), nil
}

func named(order []string) []any {
	groups := make([]any, 0, len(order))
	for _, g := range order {
		groups = append(groups, map[string]any{"name": g})
	}
	return groups
}

func groupNames(groups []any) string {
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		if m, ok := g.(map[string]any); ok {
			names = append(names, fmt.Sprint(m["name"]))
		}
	}
	return strings.Join(names, ",")
}

func routingMetadata(groups []any) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{
		"envoy.ai.routing": map[string]any{"priority_groups": groups},
	})
}

// bufferedBody makes the filter send the whole request body once the headers are answered.
var bufferedBody = &extprocfilterv3.ProcessingMode{
	RequestHeaderMode:   extprocfilterv3.ProcessingMode_SEND,
	ResponseHeaderMode:  extprocfilterv3.ProcessingMode_SKIP,
	RequestBodyMode:     extprocfilterv3.ProcessingMode_BUFFERED,
	ResponseBodyMode:    extprocfilterv3.ProcessingMode_NONE,
	RequestTrailerMode:  extprocfilterv3.ProcessingMode_SKIP,
	ResponseTrailerMode: extprocfilterv3.ProcessingMode_SKIP,
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
			groups, err := decide(headers, model)
			if err != nil {
				return err
			}
			md, err := routingMetadata(groups)
			if err != nil {
				return err
			}
			rewrite := headerValue(headers, "x-pdp-rewrite-body") != ""
			log.Printf("pdp: path=%s model=%q groups=%v rewrite=%v", headerValue(headers, ":path"),
				model, groups, rewrite)
			common := &extprocv3.CommonResponse{
				ClearRouteCache: true,
				HeaderMutation: &extprocv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{{
						Header: &corev3.HeaderValue{
							Key:      "x-pdp-decision",
							RawValue: []byte(groupNames(groups)),
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
			if !rewrite && headerValue(headers, "x-test-mutate-body") != "" {
				resp.ModeOverride = bufferedBody
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		case *extprocv3.ProcessingRequest_RequestBody:
			body := bytes.ReplaceAll(v.RequestBody.GetBody(), []byte("hello"), []byte("HELLO"))
			resp := &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_RequestBody{
					RequestBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{
						BodyMutation: &extprocv3.BodyMutation{
							Mutation: &extprocv3.BodyMutation_Body{Body: body},
						},
					}},
				},
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		default:
			return fmt.Errorf("pdp: unexpected request %T", v)
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
