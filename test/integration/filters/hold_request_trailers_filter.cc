#include <chrono>
#include <string>

#include "envoy/event/timer.h"
#include "envoy/http/filter.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/http/common/pass_through_filter.h"

#include "test/extensions/filters/http/common/empty_http_filter_config.h"
#include "test/integration/filters/common.h"
#include "test/integration/filters/test_filters.pb.h"

namespace Envoy {

// A test filter that passes headers and body through, stops iteration on the request trailers,
// and resumes decoding from a zero-delay timer.
class HoldRequestTrailersFilter : public Http::PassThroughFilter {
public:
  constexpr static char name[] = "hold-request-trailers-filter";

  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override {
    continue_timer_ = decoder_callbacks_->dispatcher().createTimer(
        [this]() -> void { decoder_callbacks_->continueDecoding(); });
    continue_timer_->enableTimer(std::chrono::milliseconds(0));
    return Http::FilterTrailersStatus::StopIteration;
  }

private:
  Event::TimerPtr continue_timer_;
};

static Registry::RegisterFactory<
    UniqueSimpleFilterConfig<HoldRequestTrailersFilter,
                             test::integration::filters::HoldRequestTrailersFilterConfig>,
    Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

} // namespace Envoy
