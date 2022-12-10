// crypto.cpp : Defines the entry point for the application.
//
#include <array>
#include <vector>
#include <algorithm>
#include "crypto.h"
namespace {
	constexpr int SHA1_BLOCK_SIZE = 512;
	std::uint32_t ROTL(std::uint32_t value, std::uint8_t pos) {
		return (value << pos) | (value >> 32 - pos);
	}
}
namespace crypto {
	
	std::vector<std::uint32_t> SHA1::get_digest(const std::string& message) {
		if (message.size() > ((uint64_t)1 << 61)) {
			throw std::invalid_argument("SHA1 cannot work with message size of more than 2^64 bits");
		}
		Hash block_hash;
		std::size_t pos = 0;
		while (pos < message.size()) {
			update_block_buffer(message, pos);
			if (block_buffer_counter < 64)
				break;
			block_hash.hash_block(block_buffer);
			pos += 64;

		}
		if (block_buffer_counter == 64) {
			clear_block_buffer();
		}
		block_buffer[block_buffer_counter++] = 0x80;
		if (block_buffer_counter > 56) {
			block_hash.hash_block(block_buffer);
			clear_block_buffer();
		}
		append_length_to_block_buffer(message.size());
		block_hash.hash_block(block_buffer);
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
		while((block_buffer_counter < SHA1_BLOCK_SIZE)&&(pos < message.size())){
			block_buffer[block_buffer_counter++] = (std::uint8_t)message[pos++];
		}		
	}
}


