#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace crypto {
	class BlockBuffer512 {
	public:
		BlockBuffer512();
		void update(const std::string& message, std::size_t pos);
		void clear();
		void append_length(std::uint64_t size);
		void add_eod_byte();
		std::size_t buffer_index() const;
		const std::vector<std::uint8_t>& get_buffer() const;
	private:
		std::vector<std::uint8_t> buffer;
		std::size_t _buffer_index = 0;
		static constexpr int BLOCK_SIZE_BYTES = 64;
	};
}