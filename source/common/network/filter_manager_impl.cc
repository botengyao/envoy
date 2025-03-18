#include "source/common/network/filter_manager_impl.h"

#include <list>

#include "envoy/network/connection.h"

#include "source/common/common/assert.h"
#include "source/common/runtime/runtime_features.h"

namespace Envoy {
namespace Network {

void FilterManagerImpl::addWriteFilter(WriteFilterSharedPtr filter) {
  ASSERT(connection_.state() == Connection::State::Open);
  ActiveWriteFilterPtr new_filter = std::make_unique<ActiveWriteFilter>(*this, filter);
  filter->initializeWriteFilterCallbacks(*new_filter);
  LinkedList::moveIntoList(std::move(new_filter), downstream_filters_);
}

void FilterManagerImpl::addFilter(FilterSharedPtr filter) {
  addReadFilter(filter);
  addWriteFilter(filter);
}

void FilterManagerImpl::addReadFilter(ReadFilterSharedPtr filter) {
  ASSERT(connection_.state() == Connection::State::Open);
  ActiveReadFilterPtr new_filter = std::make_unique<ActiveReadFilter>(*this, filter);
  filter->initializeReadFilterCallbacks(*new_filter);
  LinkedList::moveIntoListBack(std::move(new_filter), upstream_filters_);
}

void FilterManagerImpl::removeReadFilter(ReadFilterSharedPtr filter_to_remove) {
  // For perf/safety reasons, null this out rather than removing.
  for (auto& filter : upstream_filters_) {
    if (filter->filter_ == filter_to_remove) {
      filter->filter_ = nullptr;
    }
  }
}

bool FilterManagerImpl::initializeReadFilters() {
  if (upstream_filters_.empty()) {
    return false;
  }

  // Initialize read filters without calling onData() afterwards.
  // This is called just after an connection has been established and nothing may have been read
  // yet. onData() will be called separately as data is read from the connection.
  for (auto& entry : upstream_filters_) {
    if (entry->filter_ && !entry->initialized_) {
      entry->initialized_ = true;
      FilterStatus status = entry->filter_->onNewConnection();
      if (status == FilterStatus::StopIteration || connection_.state() != Connection::State::Open) {
        break;
      }
    }
  }

  return true;
}

void FilterManagerImpl::onContinueReading(ActiveReadFilter* filter,
                                          ReadBufferSource& buffer_source) {
  // Filter could return status == FilterStatus::StopIteration immediately, close the connection and
  // use callback to call this function.
  if (connection_.state() != Connection::State::Open) {
    return;
  }

  std::list<ActiveReadFilterPtr>::iterator entry;
  if (!filter) {
    connection_.streamInfo().addBytesReceived(buffer_source.getReadBuffer().buffer.length());
    entry = upstream_filters_.begin();
  } else {
    entry = std::next(filter->entry());
  }

  for (; entry != upstream_filters_.end(); entry++) {
    if (!(*entry)->filter_) {
      continue;
    }
    if (!(*entry)->initialized_) {
      (*entry)->initialized_ = true;
      FilterStatus status = (*entry)->filter_->onNewConnection();
      if (status == FilterStatus::StopIteration || connection_.state() != Connection::State::Open) {
        return;
      }
    }

    StreamBuffer read_buffer = buffer_source.getReadBuffer();
    if (read_buffer.buffer.length() > 0 || read_buffer.end_stream) {
      FilterStatus status = (*entry)->filter_->onData(read_buffer.buffer, read_buffer.end_stream);
      if (status == FilterStatus::StopIteration || connection_.state() != Connection::State::Open) {
        return;
      } else if (status == FilterStatus::StopIterationDontClose) {
        (*entry)->handleStopIterationDontClose();
        return;
      }
    }
  }
}

void FilterManagerImpl::onRead() {
  ASSERT(!upstream_filters_.empty());
  onContinueReading(nullptr, connection_);
}

bool FilterManagerImpl::startUpstreamSecureTransport() {
  for (auto& filter : upstream_filters_) {
    if (filter->filter_ != nullptr && filter->filter_->startUpstreamSecureTransport()) {
      // Success. The filter converted upstream's transport socket to secure mode.
      return true;
    }
  }
  return false;
}

void FilterManagerImpl::maybeClose() {
  ENVOY_CONN_LOG(trace,
                 "onConnectionClose: pending_remote_close_={}, pending_local_close_={}, "
                 "pending_close_write_filter_={}, pending_close_read_filter_={}",
                 connection_, state_.pending_remote_close_, state_.pending_local_close_,
                 state_.pending_close_write_filter_, state_.pending_close_read_filter_);

  // Check if we need to close the connection
  if ((state_.pending_remote_close_ || state_.pending_local_close_) &&
      (state_.pending_close_read_filter_ == 0 && state_.pending_close_write_filter_ == 0)) {
    if (latched_close_action_.has_value()) {
      ENVOY_LOG(info, "boteng latched_close_action_");
      finalizeClose(latched_close_action_.value());
    }
    return;
  }
}

void FilterManagerImpl::onConnectionClose(ConnectionCloseAction close_action) {
  // Ignore if connection is not in Open state
  if (connection_.state() != Connection::State::Open) {
    return;
  }

  ASSERT(close_action.isLocalClose() || close_action.isRemoteClose());

  ENVOY_CONN_LOG(trace,
                 "onConnectionClose: pending_remote_close_={}, pending_local_close_={}, "
                 "pending_close_write_filter_={}, pending_close_read_filter_={}",
                 connection_, state_.pending_remote_close_, state_.pending_local_close_,
                 state_.pending_close_write_filter_, state_.pending_close_read_filter_);

  latched_close_action_ = close_action;
  if (close_action.isLocalClose()) {
    state_.pending_local_close_ = true;
  } else if (close_action.isRemoteClose()) {
    state_.pending_remote_close_ = true;
  }

  // Only finalize if we have no pending filters
  // TODO(botengyao) this can be more intelligent to distinguish remote close and local close.
  if (state_.pending_close_read_filter_ == 0 && state_.pending_close_write_filter_ == 0) {
    finalizeClose(close_action);
    return;
  }

  // Otherwise, wait for filters to complete
  // The close will be finalized when both filter counts reach 0
  ENVOY_CONN_LOG(trace, "delaying close: pending read filters: {}, pending write filters: {}",
                 connection_, state_.pending_close_read_filter_,
                 state_.pending_close_write_filter_);
}

FilterStatus FilterManagerImpl::onWrite() { return onWrite(nullptr, connection_); }

FilterStatus FilterManagerImpl::onWrite(ActiveWriteFilter* filter,
                                        WriteBufferSource& buffer_source) {
  // Filter could return status == FilterStatus::StopIteration immediately, close the connection and
  // use callback to call this function.
  if (connection_.state() != Connection::State::Open) {
    return FilterStatus::StopIteration;
  }

  std::list<ActiveWriteFilterPtr>::iterator entry;
  if (!filter) {
    entry = downstream_filters_.begin();
  } else {
    entry = std::next(filter->entry());
  }

  for (; entry != downstream_filters_.end(); entry++) {
    StreamBuffer write_buffer = buffer_source.getWriteBuffer();
    FilterStatus status = (*entry)->filter_->onWrite(write_buffer.buffer, write_buffer.end_stream);
    if (status == FilterStatus::StopIteration || connection_.state() != Connection::State::Open) {
      return FilterStatus::StopIteration;
    } else if (status == FilterStatus::StopIterationDontClose) {
      (*entry)->handleStopIterationDontClose();
      // The connection write path can still check StopIteration.
      return FilterStatus::StopIteration;
    }
  }

  // Report the final bytes written to the wire
  connection_.streamInfo().addBytesSent(buffer_source.getWriteBuffer().buffer.length());
  return FilterStatus::Continue;
}

void FilterManagerImpl::onResumeWriting(ActiveWriteFilter* filter,
                                        WriteBufferSource& buffer_source) {
  auto status = onWrite(filter, buffer_source);
  if (status == FilterStatus::Continue) {
    StreamBuffer write_buffer = buffer_source.getWriteBuffer();
    ENVOY_LOG(info, "boteng onResumeWriting iteration");
    ENVOY_LOG(info, "boteng {}", write_buffer.buffer.toString());
    connection_.rawWrite(write_buffer.buffer, write_buffer.end_stream);
  }
}

} // namespace Network
} // namespace Envoy
