#include <cstring>
#include <string>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/tls/write_chunk.h"

#include "absl/strings/string_view.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
namespace {

// Appends `size` bytes of `fill` in a slice of their own, so that tests control the exact slice
// layout of the buffer.
void appendSlice(Buffer::Instance& buffer, uint64_t size, char fill) {
  auto reservation = buffer.reserveSingleSlice(size, true);
  memset(reservation.slice().mem_, fill, size);
  reservation.commit(size);
}

absl::string_view asStringView(const Buffer::RawSlice& slice) {
  return {static_cast<const char*>(slice.mem_), slice.len_};
}

TEST(NextWriteChunkTest, FullFrontSliceWrittenInPlace) {
  Buffer::OwnedImpl buffer;
  appendSlice(buffer, MaxWriteChunkSize, 'a');
  appendSlice(buffer, MaxWriteChunkSize, 'b');

  const Buffer::RawSlice front = buffer.frontSlice();
  const Buffer::RawSlice chunk = nextWriteChunk(buffer, MaxWriteChunkSize);
  EXPECT_EQ(front.mem_, chunk.mem_);
  EXPECT_EQ(MaxWriteChunkSize, chunk.len_);
}

// A front slice shorter than the chunk is written as is instead of pulling the next slice into it,
// which is what keeps the following slices aligned with the chunk boundaries.
TEST(NextWriteChunkTest, PartialFrontSliceWrittenInPlace) {
  Buffer::OwnedImpl buffer;
  appendSlice(buffer, MinWriteChunkSize, 'a');
  appendSlice(buffer, MaxWriteChunkSize, 'b');

  const Buffer::RawSlice front = buffer.frontSlice();
  const Buffer::RawSlice chunk = nextWriteChunk(buffer, MaxWriteChunkSize);
  EXPECT_EQ(front.mem_, chunk.mem_);
  EXPECT_EQ(MinWriteChunkSize, chunk.len_);
}

// A front slice below the minimum is coalesced, but only up to the minimum rather than the full
// chunk, so that the copy stays small.
TEST(NextWriteChunkTest, ShortFrontSliceCoalescedUpToMinimum) {
  Buffer::OwnedImpl buffer;
  appendSlice(buffer, 200, 'a');
  appendSlice(buffer, MaxWriteChunkSize, 'b');

  const Buffer::RawSlice front = buffer.frontSlice();
  const Buffer::RawSlice chunk = nextWriteChunk(buffer, MaxWriteChunkSize);
  EXPECT_NE(front.mem_, chunk.mem_);
  EXPECT_EQ(MinWriteChunkSize, chunk.len_);
  EXPECT_EQ(std::string(200, 'a') + std::string(MinWriteChunkSize - 200, 'b'), asStringView(chunk));
}

// A contiguous buffer below the minimum is written in place rather than copied.
TEST(NextWriteChunkTest, ShortContiguousBufferWrittenInPlace) {
  Buffer::OwnedImpl buffer;
  appendSlice(buffer, 100, 'a');

  const Buffer::RawSlice front = buffer.frontSlice();
  const Buffer::RawSlice chunk = nextWriteChunk(buffer, buffer.length());
  EXPECT_EQ(front.mem_, chunk.mem_);
  EXPECT_EQ(100, chunk.len_);
}

// A fragmented buffer below the minimum is coalesced whole, so that it goes out as one TLS record
// rather than one per slice.
TEST(NextWriteChunkTest, ShortFragmentedBufferCoalescedWhole) {
  Buffer::OwnedImpl buffer;
  appendSlice(buffer, 100, 'a');
  appendSlice(buffer, 100, 'b');

  const Buffer::RawSlice front = buffer.frontSlice();
  const Buffer::RawSlice chunk = nextWriteChunk(buffer, buffer.length());
  EXPECT_NE(front.mem_, chunk.mem_);
  EXPECT_EQ(200, chunk.len_);
  EXPECT_EQ(std::string(100, 'a') + std::string(100, 'b'), asStringView(chunk));
}

// Writes out the whole buffer the way SslSocket::doWrite does, checking that the bytes come out
// unchanged and returning the number of writes that had to copy.
uint32_t drainBuffer(Buffer::Instance& buffer, bool write_front_chunk) {
  const std::string expected = buffer.toString();
  std::string written;
  uint32_t copies = 0;

  while (buffer.length() > 0) {
    const uint64_t max_bytes = std::min<uint64_t>(buffer.length(), MaxWriteChunkSize);
    const Buffer::RawSlice front = buffer.frontSlice();
    Buffer::RawSlice chunk;
    if (write_front_chunk) {
      chunk = nextWriteChunk(buffer, max_bytes);
    } else {
      chunk = {buffer.linearize(max_bytes), static_cast<size_t>(max_bytes)};
    }
    if (chunk.mem_ != front.mem_) {
      copies++;
    }
    written.append(static_cast<const char*>(chunk.mem_), chunk.len_);
    buffer.drain(chunk.len_);
  }

  EXPECT_EQ(expected, written);
  return copies;
}

// A single short slice at the front of the buffer, as produced by response headers or a frame
// header, used to misalign every following chunk against the slice boundaries and copy the whole
// stream. It now costs one small copy, after which the buffer is written in place.
TEST(NextWriteChunkTest, ShortLeadingSliceRealignsAfterOneCopy) {
  auto fill = [](Buffer::Instance& buffer) {
    appendSlice(buffer, 200, 'h');
    for (int i = 0; i < 10; i++) {
      appendSlice(buffer, MaxWriteChunkSize, static_cast<char>('a' + i));
    }
  };

  Buffer::OwnedImpl buffer;
  fill(buffer);
  EXPECT_EQ(1, drainBuffer(buffer, true));

  // Linearizing the full chunk instead leaves an equally short slice at the front of the buffer,
  // so every full-sized write copies.
  Buffer::OwnedImpl linearized_buffer;
  fill(linearized_buffer);
  EXPECT_EQ(10, drainBuffer(linearized_buffer, false));
}

// SslSocket::doWrite re-runs the selection after SSL_ERROR_WANT_WRITE with the length pinned to
// what the previous call returned, and has to hand SSL_write the same pointer and length. Data
// appended to the buffer in between must not change either.
TEST(NextWriteChunkTest, StableAcrossAppendsForWantWriteRetry) {
  for (const uint64_t front_size : {200, 4096, 12288, 16384}) {
    Buffer::OwnedImpl buffer;
    appendSlice(buffer, front_size, 'a');
    appendSlice(buffer, MaxWriteChunkSize, 'b');

    const Buffer::RawSlice chunk =
        nextWriteChunk(buffer, std::min<uint64_t>(buffer.length(), MaxWriteChunkSize));

    appendSlice(buffer, MaxWriteChunkSize, 'c');
    buffer.add("appended while the write was blocked");

    const Buffer::RawSlice retry = nextWriteChunk(buffer, chunk.len_);
    EXPECT_EQ(chunk.mem_, retry.mem_) << "front_size " << front_size;
    EXPECT_EQ(chunk.len_, retry.len_) << "front_size " << front_size;
  }
}

// The same, for a buffer whose front slice is also its back slice, so that the append grows the
// very slice the blocked write is pointing into.
TEST(NextWriteChunkTest, StableAcrossGrowingFrontSliceForWantWriteRetry) {
  Buffer::OwnedImpl buffer;
  appendSlice(buffer, 100, 'a');

  const Buffer::RawSlice chunk = nextWriteChunk(buffer, buffer.length());
  EXPECT_EQ(100, chunk.len_);

  buffer.add("appended while the write was blocked");
  ASSERT_GT(buffer.frontSlice().len_, chunk.len_);

  const Buffer::RawSlice retry = nextWriteChunk(buffer, chunk.len_);
  EXPECT_EQ(chunk.mem_, retry.mem_);
  EXPECT_EQ(chunk.len_, retry.len_);
}

} // namespace
} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
