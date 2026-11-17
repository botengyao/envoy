#include <chrono>

#include "envoy/event/timer.h"
#include "envoy/http/filter.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/http/common/pass_through_filter.h"

#include "test/extensions/filters/http/common/empty_http_filter_config.h"
#include "test/integration/filters/common.h"
#include "test/integration/filters/test_filters.pb.h"

namespace Envoy {

// A filter that stops all iteration on the request headers and resumes once the request trailers
// have arrived. It then buffers the replayed body and only continues from decodeTrailers().
class StopAllThenBufferFilter : public Http::PassThroughFilter {
public:
  constexpr static char name[] = "stop-all-then-buffer-filter";

  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap&, bool end_stream) override {
    if (end_stream) {
      return Http::FilterHeadersStatus::Continue;
    }
    resume_timer_ = decoder_callbacks_->dispatcher().createTimer([this]() -> void {
      // The trailers are visible here before this stopped filter gets its decodeTrailers() call.
      if (decoder_callbacks_->requestTrailers().has_value()) {
        decoder_callbacks_->continueDecoding();
      } else {
        resume_timer_->enableTimer(std::chrono::milliseconds(5));
      }
    });
    resume_timer_->enableTimer(std::chrono::milliseconds(5));
    return Http::FilterHeadersStatus::StopAllIterationAndBuffer;
  }

  Http::FilterDataStatus decodeData(Buffer::Instance&, bool end_stream) override {
    return end_stream ? Http::FilterDataStatus::Continue
                      : Http::FilterDataStatus::StopIterationAndBuffer;
  }

  void onDestroy() override {
    if (resume_timer_ != nullptr) {
      resume_timer_->disableTimer();
    }
  }

private:
  Event::TimerPtr resume_timer_;
};

constexpr char StopAllThenBufferFilter::name[];
static Registry::RegisterFactory<
    UniqueSimpleFilterConfig<StopAllThenBufferFilter,
                             test::integration::filters::StopAllThenBufferFilterConfig>,
    Server::Configuration::NamedHttpFilterConfigFactory>
    register_;
static Registry::RegisterFactory<
    UniqueSimpleFilterConfig<StopAllThenBufferFilter,
                             test::integration::filters::StopAllThenBufferFilterConfig>,
    Server::Configuration::UpstreamHttpFilterConfigFactory>
    register_upstream_;

} // namespace Envoy
