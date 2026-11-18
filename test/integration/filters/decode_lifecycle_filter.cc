#include <string>

#include "envoy/http/filter.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/common/common/assert.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

#include "test/extensions/filters/http/common/empty_http_filter_config.h"
#include "test/integration/filters/common.h"
#include "test/integration/filters/test_filters.pb.h"

namespace Envoy {

// Aborts the decoder filter chain on the frame that ends the request. The "abort-phase" request
// header selects the frame ("headers", "data" or "trailers") and "abort-action" selects how
// ("local-reply", "reset" or "goaway"). decodeComplete() must run at most once and never after
// onDestroy(); a local reply reports whether it was encoded after decodeComplete().
class DecodeLifecycleFilter : public Http::PassThroughFilter {
public:
  constexpr static char name[] = "decode-lifecycle-filter";

  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers, bool) override {
    phase_ = headerValue(headers, "abort-phase");
    action_ = headerValue(headers, "abort-action");
    if (phase_ == "headers") {
      abort();
      return Http::FilterHeadersStatus::StopIteration;
    }
    return Http::FilterHeadersStatus::Continue;
  }

  Http::FilterDataStatus decodeData(Buffer::Instance&, bool end_stream) override {
    if (phase_ == "data" && end_stream) {
      abort();
      return Http::FilterDataStatus::StopIterationNoBuffer;
    }
    return Http::FilterDataStatus::Continue;
  }

  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override {
    if (phase_ == "trailers") {
      abort();
      return Http::FilterTrailersStatus::StopIteration;
    }
    return Http::FilterTrailersStatus::Continue;
  }

  void decodeComplete() override {
    RELEASE_ASSERT(!destroyed_, "decodeComplete() called after onDestroy()");
    RELEASE_ASSERT(!decode_complete_, "decodeComplete() called twice");
    decode_complete_ = true;
  }

  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers, bool) override {
    if (aborted_) {
      headers.addCopy(Http::LowerCaseString("decode-complete-before-reply"),
                      decode_complete_ ? "true" : "false");
    }
    return Http::FilterHeadersStatus::Continue;
  }

  void onDestroy() override { destroyed_ = true; }

private:
  static std::string headerValue(const Http::RequestHeaderMap& headers, absl::string_view key) {
    const auto result = headers.get(Http::LowerCaseString(key));
    return result.empty() ? "" : std::string(result[0]->value().getStringView());
  }

  void abort() {
    aborted_ = true;
    if (action_ == "local-reply") {
      decoder_callbacks_->sendLocalReply(Http::Code::Forbidden, "aborted", nullptr, std::nullopt,
                                         "decode_lifecycle_abort");
    } else if (action_ == "reset") {
      decoder_callbacks_->resetStream();
    } else if (action_ == "goaway") {
      decoder_callbacks_->sendGoAwayAndClose();
    }
  }

  std::string phase_;
  std::string action_;
  bool aborted_{};
  bool decode_complete_{};
  bool destroyed_{};
};

constexpr char DecodeLifecycleFilter::name[];
static Registry::RegisterFactory<
    UniqueSimpleFilterConfig<DecodeLifecycleFilter,
                             test::integration::filters::DecodeLifecycleFilterConfig>,
    Server::Configuration::NamedHttpFilterConfigFactory>
    register_;
static Registry::RegisterFactory<
    UniqueSimpleFilterConfig<DecodeLifecycleFilter,
                             test::integration::filters::DecodeLifecycleFilterConfig>,
    Server::Configuration::UpstreamHttpFilterConfigFactory>
    register_upstream_;

} // namespace Envoy
