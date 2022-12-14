#include "sha256.h"
#include "util.h"
#include <algorithm>
#include <stdexcept>
#include <iostream>

namespace {
constexpr int SHA256_BLOCK_SIZE_BITS = 512;
constexpr int SHA256_BLOCK_SIZE_BYTES = SHA256_BLOCK_SIZE_BITS / 8;
constexpr int SHA256_LENGTH_SIZE_BITS = 64;
constexpr int SHA256_LENGTH_SIZE_BYTES = SHA256_LENGTH_SIZE_BITS / 8;

}  // namespace

namespace crypto {
SHA256::SHA256() : block_buffer(SHA256_BLOCK_SIZE_BYTES){};

std::vector<std::uint32_t> SHA256::get_digest(const std::string& message) {
  if (message.size() > ((uint64_t)1 << 61)) {
    throw std::invalid_argument(
        "get_digest: SHA1 cannot work with message size of more than 2^64 "
        "bits");
  }
  BlockHash block_hash;
  std::size_t pos = 0;
  while (pos < message.size()) {
    update_block_buffer(message, pos);
    if (block_buffer_index < SHA256_BLOCK_SIZE_BYTES) break;
    block_hash(block_buffer);
    pos += SHA256_BLOCK_SIZE_BYTES;
  }
  if (block_buffer_index == SHA256_BLOCK_SIZE_BYTES) {
    clear_block_buffer();
  }
  block_buffer[block_buffer_index++] = 0x80;
  if (block_buffer_index > SHA256_BLOCK_SIZE_BYTES - SHA256_LENGTH_SIZE_BYTES) {
    block_hash(block_buffer);
    clear_block_buffer();
  }
  append_length_to_block_buffer(message.size() * 8);
  block_hash(block_buffer);
  return block_hash.get_digest();
}

void SHA256::append_length_to_block_buffer(std::uint64_t size) {
  for (auto it = block_buffer.end() - SHA256_LENGTH_SIZE_BYTES;
       it != block_buffer.end(); ++it) {
    *it = (size >> 56) & 0xff;
    size = size << 8;
  }
}

void SHA256::clear_block_buffer() {
  std::fill(block_buffer.begin(), block_buffer.end(), 0);
  block_buffer_index = 0;
}
void SHA256::update_block_buffer(const std::string& message, std::size_t pos) {
  if (pos >= message.size()) {
    throw std::invalid_argument(
        "update_block_buffer: pos greater than message size");
  }
  clear_block_buffer();
  while ((block_buffer_index < SHA256_BLOCK_SIZE_BYTES) &&
         (pos < message.size())) {
    block_buffer[block_buffer_index++] = (std::uint8_t)message[pos++];
  }
}

std::vector<std::uint32_t> SHA256::BlockHash::get_digest() const {
  return std::vector<std::uint32_t>{digest.begin(), digest.end()};
}

void SHA256::BlockHash::operator()(const std::vector<std::uint8_t>& block) {
  std::size_t t = 0;
  std::copy(digest.begin(), digest.end(), work_var.begin());
  while (t < 64) {
    if (t < 16) {
      W[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) |
             (block[t * 4 + 2] << 8) | (block[t * 4 + 3]);
    } else {
      W[t] = Sig1(W[t - 2]) + W[t - 7] + Sig0(W[t - 15]) + W[t - 16];
    }
    std::uint32_t temp1 = work_var[7] + Ep1(work_var[4]) +
                          Ch(work_var[4], work_var[5], work_var[6]) + K[t] +
                          W[t];
    std::uint32_t temp2 =
        Ep0(work_var[0]) + Maj(work_var[0], work_var[1], work_var[2]);
    work_var[7] = work_var[6];
    work_var[6] = work_var[5];
    work_var[5] = work_var[4];
    work_var[4] = work_var[3] + temp1;
    work_var[3] = work_var[2];
    work_var[2] = work_var[1];
    work_var[1] = work_var[0];
    work_var[0] = temp1 + temp2;
    t++;
  }
  std::transform(work_var.begin(), work_var.end(), digest.begin(),
                 digest.begin(), std::plus<>{});
}
std::uint32_t SHA256::BlockHash::Ch(std::uint32_t x, std::uint32_t y,
                                    std::uint32_t z) {
  return (x & y) ^ (~x & z);
}

std::uint32_t SHA256::BlockHash::Maj(std::uint32_t x, std::uint32_t y,
                                     std::uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}
std::uint32_t SHA256::BlockHash::Ep0(std::uint32_t x) {
  return util::ROTR(x, 2) ^ util::ROTR(x, 13) ^ util::ROTR(x, 22);
}
std::uint32_t SHA256::BlockHash::Ep1(std::uint32_t x) {
  return util::ROTR(x, 6) ^ util::ROTR(x, 11) ^ util::ROTR(x, 25);
}
std::uint32_t SHA256::BlockHash::Sig0(std::uint32_t x) {
  return util::ROTR(x, 7) ^ util::ROTR(x, 18) ^ util::SHR(x, 3);
}
std::uint32_t SHA256::BlockHash::Sig1(std::uint32_t x) {
  return util::ROTR(x, 17) ^ util::ROTR(x, 19) ^ util::SHR(x, 10);
}

}  // namespace crypto
