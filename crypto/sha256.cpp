#include <stdexcept>
#include "sha256.h"

namespace {
	constexpr int SHA256_BLOCK_SIZE_BITS = 512;
	constexpr int SHA256_BLOCK_SIZE_BYTES = SHA256_BLOCK_SIZE_BITS / 8;
	constexpr int SHA256_LENGTH_SIZE_BITS = 64;
	constexpr int SHA256_LENGTH_SIZE_BYTES = SHA256_LENGTH_SIZE_BITS / 8;

	std::uint32_t ROTR(std::uint32_t value, std::uint8_t pos) {
		return (value >> pos) | (value << (32 - pos));
	}
	std::uint32_t SHR(std::uint32_t value, std::uint8_t pos) {
		return value >> pos ;
	}
}

namespace crypto {
	SHA256::SHA256()
		: block_buffer(SHA256_BLOCK_SIZE_BYTES) {};

	std::vector<std::uint32_t> SHA256::get_digest(const std::string& message) {
		if (message.size() > ((uint64_t)1 << 61)) {
			throw std::invalid_argument("get_digest: SHA1 cannot work with message size of more than 2^64 bits");
		}
		BlockHash block_hash;
		std::size_t pos = 0;
		while (pos < message.size()) {
			update_block_buffer(message, pos);
			if (block_buffer_index < SHA256_BLOCK_SIZE_BYTES)
				break;
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
		for (auto it = block_buffer.end() - SHA256_LENGTH_SIZE_BYTES; it != block_buffer.end(); ++it) {
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
			throw std::invalid_argument("update_block_buffer: pos greater than message size");
		}
		clear_block_buffer();
		while ((block_buffer_index < SHA256_BLOCK_SIZE_BYTES) && (pos < message.size())) {
			block_buffer[block_buffer_index++] = (std::uint8_t)message[pos++];
		}
	}


}