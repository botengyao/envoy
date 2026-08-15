#include "source/common/buffer/buffer_impl.h"
#include "source/common/tls/ssl_write_chunk.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace {

// Appends `size` bytes as a slice of its own, with a `seed`-derived pattern so reassembled output
// can be compared against the original.
void appendSlice(Buffer::Instance& buffer, uint64_t size, uint8_t seed) {
  std::string data(size, 0);
  for (uint64_t i = 0; i < size; i++) {
    data[i] = static_cast<char>((seed + i) % 251);
  }
  // move() of a standalone buffer brings whole slices in, as ConnectionImpl::write() does.
  Buffer::OwnedImpl slice;
  slice.add(data);
  buffer.move(slice);
}

// The shape a proxied response produces: a short header slice ahead of full-size body slices.
void buildMisalignedBuffer(Buffer::Instance& buffer, uint64_t header_size, uint32_t body_slices) {
  appendSlice(buffer, header_size, 1);
  for (uint32_t i = 0; i < body_slices; i++) {
    appendSlice(buffer, MaxSslWriteSize, static_cast<uint8_t>(i + 2));
  }
}

uint64_t nextWriteSize(const Buffer::Instance& buffer) {
  return std::min<uint64_t>(buffer.length(), MaxSslWriteSize);
}

// A contiguous front slice is returned as-is, with no copy, regardless of the guard.
TEST(SslWriteChunkTest, ContiguousFrontSliceIsNotCopied) {
  for (const bool avoid_repeated : {false, true}) {
    Buffer::OwnedImpl buffer;
    appendSlice(buffer, MaxSslWriteSize, 7);
    const void* front = buffer.frontSlice().mem_;

    const SslWriteChunk chunk = selectSslWriteChunk(buffer, MaxSslWriteSize, false, avoid_repeated);
    EXPECT_EQ(front, chunk.data_);
    EXPECT_EQ(MaxSslWriteSize, chunk.length_);
    EXPECT_FALSE(chunk.linearized_);
  }
}

// A short front slice is linearized on the first write, exactly as before this optimization.
TEST(SslWriteChunkTest, ShortFrontSliceLinearizesOnFirstWrite) {
  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, 2);

  const SslWriteChunk chunk = selectSslWriteChunk(buffer, MaxSslWriteSize, false, true);
  EXPECT_TRUE(chunk.linearized_);
  // The full amount is still written; only the escape path shortens the record.
  EXPECT_EQ(MaxSslWriteSize, chunk.length_);
  EXPECT_EQ(buffer.frontSlice().mem_, chunk.data_);
}

// A second consecutive linearize means the chain is misaligned, so the front slice goes out
// directly: a shorter record, but no allocation and no copy.
TEST(SslWriteChunkTest, SecondConsecutiveLinearizeTakesShortRecord) {
  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, 2);
  const Buffer::RawSlice front = buffer.frontSlice();
  ASSERT_LT(front.len_, MaxSslWriteSize);

  const SslWriteChunk chunk = selectSslWriteChunk(buffer, MaxSslWriteSize, true, true);
  EXPECT_FALSE(chunk.linearized_);
  EXPECT_EQ(front.mem_, chunk.data_);
  EXPECT_EQ(front.len_, chunk.length_);
}

// With the runtime guard off, the old behavior is kept: linearize every time.
TEST(SslWriteChunkTest, GuardDisabledAlwaysLinearizes) {
  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, 2);

  const SslWriteChunk chunk = selectSslWriteChunk(buffer, MaxSslWriteSize, true, false);
  EXPECT_TRUE(chunk.linearized_);
  EXPECT_EQ(MaxSslWriteSize, chunk.length_);
}

// BoringSSL requires the retry to present the same pointer and length, so re-selecting must be
// stable even when more data was appended at the back in between.
TEST(SslWriteChunkTest, ReselectAfterWantWriteIsStable) {
  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, 2);

  // Take the escape, as if SSL_write() then returned SSL_ERROR_WANT_WRITE.
  const SslWriteChunk first = selectSslWriteChunk(buffer, MaxSslWriteSize, true, true);
  ASSERT_LT(first.length_, MaxSslWriteSize);

  // More response data arrives before the retry.
  appendSlice(buffer, MaxSslWriteSize, 42);

  // The retry asks for exactly the pending length and must get the same memory back.
  const SslWriteChunk retry = selectSslWriteChunk(buffer, first.length_, false, true);
  EXPECT_EQ(first.data_, retry.data_);
  EXPECT_EQ(first.length_, retry.length_);
  EXPECT_FALSE(retry.linearized_);
}

// The point of the change: copying stops after one linearize, and the bytes handed to SSL_write()
// still reconstruct the original stream exactly.
TEST(SslWriteChunkTest, MisalignedBufferCopiesOnceAndPreservesBytes) {
  constexpr uint32_t BodySlices = 8;
  Buffer::OwnedImpl expected;
  buildMisalignedBuffer(expected, 200, BodySlices);
  const std::string expected_bytes = expected.toString();

  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, BodySlices);

  std::string written;
  uint32_t linearize_count = 0;
  uint32_t write_count = 0;
  bool linearized_last_write = false;
  while (buffer.length() > 0) {
    const SslWriteChunk chunk =
        selectSslWriteChunk(buffer, nextWriteSize(buffer), linearized_last_write, true);
    linearized_last_write = chunk.linearized_;
    if (chunk.linearized_) {
      linearize_count++;
    }
    written.append(static_cast<const char*>(chunk.data_), chunk.length_);
    buffer.drain(chunk.length_);
    write_count++;
    ASSERT_LT(write_count, 100) << "write loop failed to make progress";
  }

  EXPECT_EQ(expected_bytes, written);
  // One copy to start, then the short record re-aligns the chain and nothing copies again.
  EXPECT_EQ(1, linearize_count);
}

// Same buffer, guard off: every single write copies, which is the behavior being fixed.
TEST(SslWriteChunkTest, MisalignedBufferCopiesEveryWriteWithGuardDisabled) {
  constexpr uint32_t BodySlices = 8;
  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, BodySlices);

  uint32_t linearize_count = 0;
  uint32_t write_count = 0;
  bool linearized_last_write = false;
  while (buffer.length() > 0) {
    const SslWriteChunk chunk =
        selectSslWriteChunk(buffer, nextWriteSize(buffer), linearized_last_write, false);
    linearized_last_write = chunk.linearized_;
    if (chunk.linearized_) {
      linearize_count++;
    }
    buffer.drain(chunk.length_);
    write_count++;
    ASSERT_LT(write_count, 100) << "write loop failed to make progress";
  }

  // Every write but the last (which is short enough to be contiguous) has to copy.
  EXPECT_EQ(BodySlices, linearize_count);
}

// Drives the selector as SslSocket::doWrite() does. `want_write_at` forces one
// SSL_ERROR_WANT_WRITE before the write at that index succeeds.
struct DriveResult {
  uint32_t linearize_count{0};
  uint32_t write_count{0};
  std::string written;
};

DriveResult drive(SslWriteChunkSelector& selector, Buffer::Instance& buffer,
                  std::optional<uint32_t> want_write_at = std::nullopt) {
  DriveResult result;
  bool want_write_pending = false;
  while (buffer.length() > 0) {
    const uint64_t bytes_to_write =
        selector.pendingLength().value_or(std::min<uint64_t>(buffer.length(), MaxSslWriteSize));
    // Count copies by watching the front of the buffer move: a copy made by an attempt that then
    // fails with WANT_WRITE is real work, and the retry reusing it must not count twice.
    const void* front_before = buffer.frontSlice().mem_;
    const SslWriteChunk chunk = selector.nextChunk(buffer, bytes_to_write);
    if (buffer.frontSlice().mem_ != front_before) {
      result.linearize_count++;
    }

    if (want_write_at.has_value() && *want_write_at == result.write_count && !want_write_pending) {
      // WANT_WRITE: nothing is drained, and the same write is retried on the next pass.
      selector.onWantWrite(chunk);
      want_write_pending = true;
      continue;
    }
    want_write_pending = false;

    result.written.append(static_cast<const char*>(chunk.data_), chunk.length_);
    // Production order: discharge before draining.
    selector.onWriteSucceeded(chunk);
    buffer.drain(chunk.length_);
    result.write_count++;
    RELEASE_ASSERT(result.write_count < 100, "write loop failed to make progress");
  }
  return result;
}

// The end-to-end behavior the change exists for, driven through the selector's state machine.
TEST(SslWriteChunkSelectorTest, MisalignedBufferCopiesOnce) {
  Buffer::OwnedImpl expected;
  buildMisalignedBuffer(expected, 200, 8);
  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, 8);

  SslWriteChunkSelector selector(true);
  const DriveResult result = drive(selector, buffer);
  EXPECT_EQ(expected.toString(), result.written);
  EXPECT_EQ(1, result.linearize_count);
}

// A retried write must be repeated verbatim without erasing the fact that it came from a
// linearize; re-deciding would see the buffer already linearized and copy again on the next write.
TEST(SslWriteChunkSelectorTest, WantWriteOnLinearizedChunkKeepsHistory) {
  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, 3);
  SslWriteChunkSelector selector(true);

  // First write linearizes, then reports WANT_WRITE.
  const SslWriteChunk first = selector.nextChunk(buffer, MaxSslWriteSize);
  ASSERT_TRUE(first.linearized_);
  selector.onWantWrite(first);

  // The retry repeats it exactly - same pointer, same length - and still knows it was a copy.
  ASSERT_TRUE(selector.pendingLength().has_value());
  EXPECT_EQ(first.length_, *selector.pendingLength());
  const SslWriteChunk retry = selector.nextChunk(buffer, *selector.pendingLength());
  EXPECT_EQ(first.data_, retry.data_);
  EXPECT_EQ(first.length_, retry.length_);
  EXPECT_TRUE(retry.linearized_);

  // Once it lands, the short remainder takes the escape rather than being copied again.
  selector.onWriteSucceeded(retry);
  buffer.drain(retry.length_);
  const SslWriteChunk next = selector.nextChunk(buffer, MaxSslWriteSize);
  EXPECT_FALSE(next.linearized_);
  EXPECT_EQ(buffer.frontSlice().len_, next.length_);
}

// Same property, exercised over a whole buffer: backpressure must not cost extra copies.
TEST(SslWriteChunkSelectorTest, WantWriteDoesNotCostExtraCopies) {
  for (uint32_t want_write_at = 0; want_write_at < 4; want_write_at++) {
    Buffer::OwnedImpl expected;
    buildMisalignedBuffer(expected, 200, 8);
    Buffer::OwnedImpl buffer;
    buildMisalignedBuffer(buffer, 200, 8);

    SslWriteChunkSelector selector(true);
    const DriveResult result = drive(selector, buffer, want_write_at);
    EXPECT_EQ(expected.toString(), result.written) << "want_write_at " << want_write_at;
    EXPECT_EQ(1, result.linearize_count) << "want_write_at " << want_write_at;
  }
}

// When the write covers the whole buffer there is no chain left to re-align, so linearizing keeps
// the batch to a single record instead of splitting it in two.
TEST(SslWriteChunkSelectorTest, NoShortRecordWhenTheWriteDrainsTheBuffer) {
  // The second slice must be at least Buffer::CopyThreshold or move() would coalesce the two.
  Buffer::OwnedImpl buffer;
  appendSlice(buffer, 200, 1);
  appendSlice(buffer, 2000, 2);
  ASSERT_EQ(2, buffer.getRawSlices().size());
  ASSERT_LT(buffer.length(), MaxSslWriteSize);

  // Even with a copy on the previous write, this one covers everything queued, so it linearizes.
  const SslWriteChunk chunk = selectSslWriteChunk(buffer, buffer.length(), true, true);
  EXPECT_TRUE(chunk.linearized_);
  EXPECT_EQ(2200, chunk.length_);
}

// A congested socket that accepts less than one record per write-ready event, so every write
// reports WANT_WRITE first. Losing the history on each retry would disable the optimization
// entirely.
TEST(SslWriteChunkSelectorTest, SustainedWantWriteStillCopiesOnce) {
  Buffer::OwnedImpl expected;
  buildMisalignedBuffer(expected, 200, 8);
  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, 8);

  SslWriteChunkSelector selector(true);
  std::string written;
  uint32_t copies = 0;
  uint32_t writes = 0;
  while (buffer.length() > 0) {
    const uint64_t bytes_to_write =
        selector.pendingLength().value_or(std::min<uint64_t>(buffer.length(), MaxSslWriteSize));

    // Attempt: the socket refuses it.
    const void* front_before = buffer.frontSlice().mem_;
    const SslWriteChunk attempt = selector.nextChunk(buffer, bytes_to_write);
    if (buffer.frontSlice().mem_ != front_before) {
      copies++;
    }
    selector.onWantWrite(attempt);

    // Retry: the same write, which now lands.
    ASSERT_TRUE(selector.pendingLength().has_value());
    const SslWriteChunk retry = selector.nextChunk(buffer, *selector.pendingLength());
    EXPECT_EQ(attempt.data_, retry.data_);
    EXPECT_EQ(attempt.length_, retry.length_);
    written.append(static_cast<const char*>(retry.data_), retry.length_);
    selector.onWriteSucceeded(retry);
    buffer.drain(retry.length_);
    writes++;
    RELEASE_ASSERT(writes < 100, "write loop failed to make progress");
  }

  EXPECT_EQ(expected.toString(), written);
  EXPECT_EQ(1, copies);
}

// With the guard off every fragmented write copies, exactly as before the change.
TEST(SslWriteChunkSelectorTest, GuardDisabledCopiesEveryWriteEvenWithWantWrite) {
  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, 8);

  SslWriteChunkSelector selector(false);
  const DriveResult result = drive(selector, buffer, /*want_write_at=*/1);
  EXPECT_EQ(8, result.linearize_count);
}

// The history is connection-scoped, so a request/response connection stays copy-free instead of
// re-linearizing once per response.
TEST(SslWriteChunkSelectorTest, HistoryCarriesAcrossBatches) {
  SslWriteChunkSelector selector(true);

  // Batch A ends on a linearize, which is what leaves the history set.
  Buffer::OwnedImpl batch_a;
  appendSlice(batch_a, 200, 1);
  appendSlice(batch_a, 2000, 2);
  const DriveResult a = drive(selector, batch_a);
  EXPECT_EQ(1, a.linearize_count);
  EXPECT_EQ(0, batch_a.length());

  // Batch B is a full-size response. Because the history carried over, its leading fragment goes
  // out as a short record and the batch copies nothing at all.
  Buffer::OwnedImpl expected_b;
  buildMisalignedBuffer(expected_b, 200, 4);
  Buffer::OwnedImpl batch_b;
  buildMisalignedBuffer(batch_b, 200, 4);
  const DriveResult b = drive(selector, batch_b);
  EXPECT_EQ(expected_b.toString(), b.written);
  EXPECT_EQ(0, b.linearize_count);
}

// Records and copied bytes for a whole buffer, so guard on and off can be compared directly.
struct Cost {
  uint32_t records{0};
  uint64_t copied_bytes{0};
};

Cost costOf(Buffer::Instance& buffer, bool avoid_repeated_linearize,
            bool linearized_last_write = false) {
  Cost cost;
  while (buffer.length() > 0) {
    const uint64_t bytes_to_write = nextWriteSize(buffer);
    const SslWriteChunk chunk = selectSslWriteChunk(buffer, bytes_to_write, linearized_last_write,
                                                    avoid_repeated_linearize);
    linearized_last_write = chunk.linearized_;
    if (chunk.linearized_) {
      cost.copied_bytes += chunk.length_;
    }
    buffer.drain(chunk.length_);
    cost.records++;
    RELEASE_ASSERT(cost.records < 10000, "write loop failed to make progress");
  }
  return cost;
}

void buildUniformSlices(Buffer::Instance& buffer, uint64_t slice_size, uint32_t count) {
  for (uint32_t i = 0; i < count; i++) {
    appendSlice(buffer, slice_size, static_cast<uint8_t>(i));
  }
}

// A chain of uniform sub-16KB slices is fragmented more than one slice deep, so writing the front
// slice re-aligns nothing and the short record would be pure overhead. The escape must not fire.
TEST(SslWriteChunkTest, UniformFragmentsAreNotWorsened) {
  // 16384 % slice_size is small for these, so a short record would carry almost no payload.
  for (const uint64_t slice_size : {1024, 4096, 4097, 5462, 8193}) {
    Buffer::OwnedImpl with_guard;
    buildUniformSlices(with_guard, slice_size, 64);
    Buffer::OwnedImpl without_guard;
    buildUniformSlices(without_guard, slice_size, 64);

    const Cost on = costOf(with_guard, true);
    const Cost off = costOf(without_guard, false);
    EXPECT_EQ(off.records, on.records) << "slice_size " << slice_size;
    EXPECT_LE(on.copied_bytes, off.copied_bytes) << "slice_size " << slice_size;
  }
}

// A slice larger than the write size self-heals: one linearize leaves a contiguous remainder.
// Splitting a short record off in front of it can cost an extra write to save a single copy, so the
// escape must decline - including when history carried in from an earlier batch says it copied.
TEST(SslWriteChunkTest, OversizedSecondSliceNeverCostsAnExtraWrite) {
  for (const uint64_t second : {20000, 24576, 32768, 33000, 40000}) {
    Buffer::OwnedImpl expected;
    appendSlice(expected, 200, 1);
    appendSlice(expected, second, 2);
    Buffer::OwnedImpl with_guard;
    appendSlice(with_guard, 200, 1);
    appendSlice(with_guard, second, 2);
    Buffer::OwnedImpl without_guard;
    appendSlice(without_guard, 200, 1);
    appendSlice(without_guard, second, 2);

    // linearized_last_write starts true, as it would after an earlier batch ended on a copy.
    const Cost on = costOf(with_guard, true, /*linearized_last_write=*/true);
    const Cost off = costOf(without_guard, false, /*linearized_last_write=*/true);
    EXPECT_LE(on.records, off.records) << "second slice " << second;
    EXPECT_LE(on.copied_bytes, off.copied_bytes) << "second slice " << second;
  }
}

// The target shape keeps its full win: the short record replaces what would have been a trailing
// write, so the record count is unchanged and one copy remains for the whole buffer.
TEST(SslWriteChunkTest, MisalignedChainKeepsItsWin) {
  Buffer::OwnedImpl with_guard;
  buildMisalignedBuffer(with_guard, 300, 16);
  Buffer::OwnedImpl without_guard;
  buildMisalignedBuffer(without_guard, 300, 16);

  const Cost on = costOf(with_guard, true);
  const Cost off = costOf(without_guard, false);
  EXPECT_EQ(off.records, on.records);
  // One copy at the start, versus one per full-size slice.
  EXPECT_EQ(MaxSslWriteSize, on.copied_bytes);
  EXPECT_EQ(16 * MaxSslWriteSize, off.copied_bytes);
}

// An aligned buffer must not be made worse: it never copies and never emits a short record.
TEST(SslWriteChunkTest, AlignedBufferNeverCopiesOrShortens) {
  Buffer::OwnedImpl buffer;
  for (uint32_t i = 0; i < 4; i++) {
    appendSlice(buffer, MaxSslWriteSize, static_cast<uint8_t>(i));
  }

  uint32_t writes = 0;
  bool linearized_last_write = false;
  while (buffer.length() > 0) {
    const SslWriteChunk chunk =
        selectSslWriteChunk(buffer, nextWriteSize(buffer), linearized_last_write, true);
    linearized_last_write = chunk.linearized_;
    EXPECT_FALSE(chunk.linearized_);
    EXPECT_EQ(MaxSslWriteSize, chunk.length_);
    buffer.drain(chunk.length_);
    writes++;
  }
  EXPECT_EQ(4, writes);
}

} // namespace
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
