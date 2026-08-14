#include "source/common/buffer/buffer_impl.h"
#include "source/common/tls/ssl_socket.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace {

// The most that is ever handed to a single SSL_write(), and also Slice::default_slice_size_.
constexpr uint64_t MaxWrite = 16384;

// Appends `size` bytes as a slice of its own, filled with a byte pattern derived from `seed` so
// that reassembled output can be compared against the original.
void appendSlice(Buffer::Instance& buffer, uint64_t size, uint8_t seed) {
  std::string data(size, 0);
  for (uint64_t i = 0; i < size; i++) {
    data[i] = static_cast<char>((seed + i) % 251);
  }
  // add() of a standalone buffer moves whole slices in, which is what ConnectionImpl::write() does
  // and is what produces the misaligned chains this function has to cope with.
  Buffer::OwnedImpl slice;
  slice.add(data);
  buffer.move(slice);
}

// Builds the shape a proxied response produces: a short header slice ahead of full-size body
// slices. See ConnectionImpl::write() -> write_buffer_->move(data).
void buildMisalignedBuffer(Buffer::Instance& buffer, uint64_t header_size, uint32_t body_slices) {
  appendSlice(buffer, header_size, 1);
  for (uint32_t i = 0; i < body_slices; i++) {
    appendSlice(buffer, MaxWrite, static_cast<uint8_t>(i + 2));
  }
}

uint64_t nextWriteSize(const Buffer::Instance& buffer) {
  return std::min<uint64_t>(buffer.length(), MaxWrite);
}

// A contiguous front slice is returned as-is, with no copy, regardless of the guard.
TEST(SslWriteChunkTest, ContiguousFrontSliceIsNotCopied) {
  for (const bool avoid_repeated : {false, true}) {
    Buffer::OwnedImpl buffer;
    appendSlice(buffer, MaxWrite, 7);
    const void* front = buffer.frontSlice().mem_;

    const SslWriteChunk chunk = selectSslWriteChunk(buffer, MaxWrite, false, avoid_repeated);
    EXPECT_EQ(front, chunk.data_);
    EXPECT_EQ(MaxWrite, chunk.length_);
    EXPECT_FALSE(chunk.linearized_);
  }
}

// A short front slice is linearized on the first write, exactly as before this optimization.
TEST(SslWriteChunkTest, ShortFrontSliceLinearizesOnFirstWrite) {
  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, 2);

  const SslWriteChunk chunk = selectSslWriteChunk(buffer, MaxWrite, false, true);
  EXPECT_TRUE(chunk.linearized_);
  // The full amount is still written; only the escape path shortens the record.
  EXPECT_EQ(MaxWrite, chunk.length_);
  EXPECT_EQ(buffer.frontSlice().mem_, chunk.data_);
}

// A second consecutive linearize means the chain is permanently misaligned, so the front slice is
// written directly instead - a shorter record, but no allocation and no copy.
TEST(SslWriteChunkTest, SecondConsecutiveLinearizeTakesShortRecord) {
  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, 2);
  const Buffer::RawSlice front = buffer.frontSlice();
  ASSERT_LT(front.len_, MaxWrite);

  const SslWriteChunk chunk = selectSslWriteChunk(buffer, MaxWrite, true, true);
  EXPECT_FALSE(chunk.linearized_);
  EXPECT_EQ(front.mem_, chunk.data_);
  EXPECT_EQ(front.len_, chunk.length_);
}

// With the runtime guard off, the old behavior is kept: linearize every time.
TEST(SslWriteChunkTest, GuardDisabledAlwaysLinearizes) {
  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, 2);

  const SslWriteChunk chunk = selectSslWriteChunk(buffer, MaxWrite, true, false);
  EXPECT_TRUE(chunk.linearized_);
  EXPECT_EQ(MaxWrite, chunk.length_);
}

// SSL_write() must be retried with the same pointer and length after SSL_ERROR_WANT_WRITE, and
// BoringSSL is not configured with SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER. Nothing is drained on a
// failed write, so re-selecting must be stable - including after the escape shortened the record,
// and including when more data was appended at the back in between.
TEST(SslWriteChunkTest, ReselectAfterWantWriteIsStable) {
  Buffer::OwnedImpl buffer;
  buildMisalignedBuffer(buffer, 200, 2);

  // Take the escape, as if SSL_write() then returned SSL_ERROR_WANT_WRITE.
  const SslWriteChunk first = selectSslWriteChunk(buffer, MaxWrite, true, true);
  ASSERT_LT(first.length_, MaxWrite);

  // More response data arrives before the retry.
  appendSlice(buffer, MaxWrite, 42);

  // The retry asks for exactly bytes_to_retry_ bytes and must get the same memory back.
  const SslWriteChunk retry = selectSslWriteChunk(buffer, first.length_, false, true);
  EXPECT_EQ(first.data_, retry.data_);
  EXPECT_EQ(first.length_, retry.length_);
  EXPECT_FALSE(retry.linearized_);
}

// The point of the change: drain a realistically misaligned buffer and confirm that the copying
// stops after one linearize instead of repeating for every slice, and that the bytes handed to
// SSL_write() still reconstruct the original stream exactly.
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

// An aligned buffer must not be made worse: it never copies and never emits a short record.
TEST(SslWriteChunkTest, AlignedBufferNeverCopiesOrShortens) {
  Buffer::OwnedImpl buffer;
  for (uint32_t i = 0; i < 4; i++) {
    appendSlice(buffer, MaxWrite, static_cast<uint8_t>(i));
  }

  uint32_t writes = 0;
  bool linearized_last_write = false;
  while (buffer.length() > 0) {
    const SslWriteChunk chunk =
        selectSslWriteChunk(buffer, nextWriteSize(buffer), linearized_last_write, true);
    linearized_last_write = chunk.linearized_;
    EXPECT_FALSE(chunk.linearized_);
    EXPECT_EQ(MaxWrite, chunk.length_);
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
