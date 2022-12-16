// crypto.cpp : Defines the entry point for the application.
//
#include "sha1.h"
#include "util.h"
#include <algorithm>
#include <stdexcept>


namespace {
constexpr int SHA1_BLOCK_SIZE_BITS = 512;
constexpr int SHA1_BLOCK_SIZE_BYTES = SHA1_BLOCK_SIZE_BITS / 8;
constexpr int SHA1_LENGTH_SIZE_BITS = 64;
constexpr int SHA1_LENGTH_SIZE_BYTES = SHA1_LENGTH_SIZE_BITS / 8;

}  // namespace
namespace crypto {

std::vector<std::uint32_t> SHA1::get_digest(const std::string& message) {
  if (message.size() > ((uint64_t)1 << 61)) {
    throw std::invalid_argument(
        "get_digest: SHA1 cannot work with message size of more than 2^64 "
        "bits");
  }
  BlockHash block_hash;
  std::size_t pos = 0;
  while (pos < message.size()) {
    block_buffer.update(message, pos);
    if (block_buffer.buffer_index() < SHA1_BLOCK_SIZE_BYTES) break;
    block_hash(block_buffer.get_buffer());
    pos += SHA1_BLOCK_SIZE_BYTES;
  }
  if (block_buffer.buffer_index() == SHA1_BLOCK_SIZE_BYTES) {
    block_buffer.clear();
  }
  block_buffer.add_eod_byte();

  if (block_buffer.buffer_index() > SHA1_BLOCK_SIZE_BYTES - SHA1_LENGTH_SIZE_BYTES) {
    block_hash(block_buffer.get_buffer());
    block_buffer.clear();
  }
  block_buffer.append_length(message.size() * 8);
  block_hash(block_buffer.get_buffer());
  return block_hash.get_digest();
}

void SHA1::BlockHash::operator()(const std::vector<std::uint8_t>& block) {
  std::size_t t = 0;
  std::copy(digest.begin(), digest.end(), work_var.begin());
  while (t < 80) {
    if (t < 16) {
      W[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) |
             (block[t * 4 + 2] << 8) | (block[t * 4 + 3]);
    } else {
      W[t] = util::ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }
    std::uint32_t temp = util::ROTL(work_var[0], 5) +
                         f(work_var[1], work_var[2], work_var[3], t) +
                         work_var[4] + K(t) + W[t];
    work_var[4] = work_var[3];
    work_var[3] = work_var[2];
    work_var[2] = util::ROTL(work_var[1], 30);
    work_var[1] = work_var[0];
    work_var[0] = temp;
    t++;
  }
  std::transform(work_var.begin(), work_var.end(), digest.begin(),
                 digest.begin(), std::plus<>{});
}

std::vector<std::uint32_t> SHA1::BlockHash::get_digest() {
  return std::vector<std::uint32_t>{digest.begin(), digest.end()};
}

std::uint32_t SHA1::BlockHash::f(std::uint32_t x, std::uint32_t y,
                                 std::uint32_t z, std::size_t index) {
  if (index < 20) {
    return (x & y) ^ (~x & z);
  } else if (((index >= 20) && (index < 40)) ||
             ((index >= 60) && (index < 80))) {
    return x ^ y ^ z;
  } else if ((index >= 40) && (index < 60)) {
    return (x & y) ^ (x & z) ^ (y & z);
  } else
    throw std::invalid_argument("f:index argument invalid");
}

std::uint32_t SHA1::BlockHash::K(std::size_t index) {
  if (index < 20)
    return 0x5a827999;
  else if (index < 40)
    return 0x6ed9eba1;
  else if (index < 60)
    return 0x8f1bbcdc;
  else if (index < 80)
    return 0xca62c1d6;
  else
    throw std::invalid_argument("K: invalid index value");
}
}  // namespace crypto