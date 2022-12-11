// crypto.cpp : Defines the entry point for the application.
//
#include <array>
#include <vector>
#include <algorithm>
#include <iomanip>
#include "crypto.h"

namespace {
	constexpr int SHA1_BLOCK_SIZE_BITS = 512 ;
	constexpr int SHA1_BLOCK_SIZE_BYTES = SHA1_BLOCK_SIZE_BITS / 8;
	std::uint32_t ROTL(std::uint32_t value, std::uint8_t pos) {
		return (value << pos) | (value >> (32 - pos));
	}
}
namespace crypto {
	SHA1::SHA1()
		: block_buffer(SHA1_BLOCK_SIZE_BYTES) {};

	std::vector<std::uint32_t> SHA1::get_digest(const std::string& message) {
		if (message.size() > ((uint64_t)1 << 61)) {
			throw std::invalid_argument("SHA1 cannot work with message size of more than 2^64 bits");
		}
		BlockHash block_hash;
		std::size_t pos = 0;
		while (pos < message.size()) {
			update_block_buffer(message, pos);
			if (block_buffer_counter < 64)
				break;
			block_hash(block_buffer);
			pos += 64;

		}
		if (block_buffer_counter == 64) {
			clear_block_buffer();
		}
		block_buffer[block_buffer_counter++] = 0x80;
		if (block_buffer_counter > 56) {
			block_hash(block_buffer);
			clear_block_buffer();
		}
		append_length_to_block_buffer(message.size()*8);
		block_hash(block_buffer);
		return block_hash.get_digest();
	}

	void SHA1::append_length_to_block_buffer(std::uint64_t size) {
		for (auto it = block_buffer.end() - 8; it != block_buffer.end(); ++it) {
			*it = (uint8_t)(size >> 56);
			size = size << 8;
		}
	}

	void SHA1::clear_block_buffer() {
		std::fill(block_buffer.begin(), block_buffer.end(), 0);
		block_buffer_counter = 0;
	}
	void SHA1::update_block_buffer(const std::string& message, std::size_t pos) {
		if (pos >= message.size()) {
			throw std::invalid_argument("get_block: start_pos greater than message size");
		}
		clear_block_buffer();
		while((block_buffer_counter < SHA1_BLOCK_SIZE_BYTES)&&(pos < message.size())){
			block_buffer[block_buffer_counter++] = (std::uint8_t)message[pos++];
		}		
	}

	void SHA1::BlockHash::operator()(const std::vector<std::uint8_t>& block) {
		std::size_t t = 0;
		std::copy(digest.begin(), digest.end(), work_var.begin());
		while (t < 80) {
			if (t < 16) {
				W[t] = (block[t * 4] << 24)
					| (block[t * 4 + 1] << 16)
					| (block[t * 4 + 2] << 8)
					| (block[t * 4 + 3]);
			}
			else {
				W[t] = ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
			}
			std::uint32_t temp = ROTL(work_var[0], 5) + func(work_var[1],
				work_var[2],
				work_var[3], t) + work_var[4] + get_const(t) + W[t];
			work_var[4] = work_var[3];
			work_var[3] = work_var[2];
			work_var[2] = ROTL(work_var[1], 30);
			work_var[1] = work_var[0];
			work_var[0] = temp;
			t++;
		}
		std::transform(work_var.begin(), work_var.end(), digest.begin(), digest.begin(), std::plus<>{});
	}

	std::vector<std::uint32_t> SHA1::BlockHash::get_digest() {
		return std::vector<std::uint32_t>{digest.begin(), digest.end()};
	}

	std::uint32_t SHA1::BlockHash::func(std::uint32_t x, std::uint32_t y, std::uint32_t z, std::size_t counter) {
		if (counter < 20) {
			return (x & y) ^ (~x & z);
		}
		else if (
			((counter >= 20) && (counter < 40))
			|| ((counter >= 60) && (counter < 80))
			) {
			return x ^ y ^ z;
		}
		else if ((counter >= 40) && (counter < 60)) {
			return (x & y) ^ (x & z) ^ (y & z);
		}
		else throw std::invalid_argument("counter argument invalid");
	}

	std::uint32_t SHA1::BlockHash::get_const(std::size_t counter) {
		if (counter < 20) return 0x5a827999;
		else if (counter < 40) return 0x6ed9eba1;
		else if (counter < 60) return 0x8f1bbcdc;
		else if (counter < 80) return 0xca62c1d6;
		else throw std::invalid_argument("invalid counter value");
	}
}
