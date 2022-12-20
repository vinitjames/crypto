#include "sha512.h"


#include <algorithm>
#include <iostream>
#include <stdexcept>

#include "util.h"


namespace {
    constexpr int SHA512_BLOCK_SIZE_BITS = 1024;
    constexpr int SHA512_BLOCK_SIZE_BYTES = SHA512_BLOCK_SIZE_BITS / 8;
    constexpr int SHA512_LENGTH_SIZE_BITS = 128;
    constexpr int SHA512_LENGTH_SIZE_BYTES = SHA512_LENGTH_SIZE_BITS / 8;

}  // namespace

namespace crypto {
    
    SHA512::SHA512(const std::array<std::uint64_t, 8>& initial_digest) {
        block_hash.set_digest(initial_digest);
    }

    std::vector<std::uint64_t> SHA512::get_digest(const std::string& message) {
        
        // BlockHash block_hash;
        std::size_t pos = 0;
        while (pos < message.size()) {
            block_buffer.update(message, pos);
            if (block_buffer.buffer_index() < SHA512_BLOCK_SIZE_BYTES) break;
            block_hash(block_buffer.get_buffer());
            pos += SHA512_BLOCK_SIZE_BYTES;
        }
        if (block_buffer.buffer_index() == SHA512_BLOCK_SIZE_BYTES) {
            block_buffer.clear();
        }
        block_buffer.add_eod_byte();
        if (block_buffer.buffer_index() >
            SHA512_BLOCK_SIZE_BYTES - SHA512_LENGTH_SIZE_BYTES) {
            block_hash(block_buffer.get_buffer());
            block_buffer.clear();
        }
        block_buffer.append_length(0, message.size() * 8);
        block_hash(block_buffer.get_buffer());
        return block_hash.get_digest();
    }

    std::vector<std::uint64_t> SHA512::BlockHash::get_digest() const {
        return std::vector<std::uint64_t>{digest.begin(), digest.end()};
    }
    void SHA512::BlockHash::set_digest(
        const std::array<std::uint64_t, 8>& new_digest) {
        digest = new_digest;
    }
    void SHA512::BlockHash::operator()(const std::vector<std::uint8_t>& block) {
        std::size_t t = 0;
        std::copy(digest.begin(), digest.end(), work_var.begin());
        while (t < 80) {
            if (t < 16) {
                W[t] = (static_cast<std::uint64_t>(block[t * 8]) << 56) | (static_cast<std::uint64_t>(block[t * 8 + 1]) << 48) |
                    (static_cast<std::uint64_t>(block[t * 8 + 2]) << 40) | (static_cast<std::uint64_t>(block[t * 8 + 3]) << 32) |
                    (static_cast<std::uint64_t>(block[t * 8 + 4]) << 24) | (static_cast<std::uint64_t>(block[t * 8 + 5]) << 16) |
                    (static_cast<std::uint64_t>(block[t * 8 + 6]) << 8) | static_cast<std::uint64_t>(block[t * 8 + 7]);
            }
            else {
                W[t] = Sig1(W[t - 2]) + W[t - 7] + Sig0(W[t - 15]) + W[t - 16];
            }
            std::uint64_t temp1 = work_var[7] + Ep1(work_var[4]) +
                Ch(work_var[4], work_var[5], work_var[6]) + K[t] +
                W[t];
            std::uint64_t temp2 =
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
    std::uint64_t SHA512::BlockHash::Ch(std::uint64_t x, std::uint64_t y,
        std::uint64_t z) {
        return (x & y) ^ (~x & z);
    }

    std::uint64_t SHA512::BlockHash::Maj(std::uint64_t x, std::uint64_t y,
        std::uint64_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    std::uint64_t SHA512::BlockHash::Ep0(std::uint64_t x) {
        return util::ROTR(x, 28) ^ util::ROTR(x, 34) ^ util::ROTR(x, 39);
    }
    std::uint64_t SHA512::BlockHash::Ep1(std::uint64_t x) {
        return util::ROTR(x, 14) ^ util::ROTR(x, 18) ^ util::ROTR(x, 41);
    }
    std::uint64_t SHA512::BlockHash::Sig0(std::uint64_t x) {
        return util::ROTR(x, 1) ^ util::ROTR(x, 8) ^ util::SHR(x, 7);
    }
    std::uint64_t SHA512::BlockHash::Sig1(std::uint64_t x) {
        return util::ROTR(x, 19) ^ util::ROTR(x, 61) ^ util::SHR(x, 6);
    }

}  // namespace crypto
