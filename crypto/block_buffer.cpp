#include "block_buffer.h"

#include <stdexcept>

namespace crypto {

BlockBuffer512::BlockBuffer512() : buffer(BLOCK_SIZE_BYTES) {}

void BlockBuffer512::append_length(std::uint64_t size) {
  for (auto it = buffer.end() - 8; it != buffer.end(); ++it) {
    *it = (size >> 56) & 0xff;
    size = size << 8;
  }
  _buffer_index += 8;
}

void BlockBuffer512::clear() {
  std::fill(buffer.begin(), buffer.end(), 0);
  _buffer_index = 0;
}

void BlockBuffer512::update(const std::string& message, std::size_t pos) {
  if (pos >= message.size()) {
    throw std::invalid_argument(
        "BlockBuffer512::update: pos greater than message size");
  }
  clear();
  std::size_t bytes_to_copy = (message.size() - pos) > BLOCK_SIZE_BYTES
                                  ? BLOCK_SIZE_BYTES
                                  : message.size() - pos;
  std::copy(message.begin() + pos, message.begin() + pos + bytes_to_copy,
            buffer.begin());
  _buffer_index = bytes_to_copy;
}

void BlockBuffer512::add_eod_byte() { buffer[_buffer_index++] = 0x80; }

std::size_t BlockBuffer512::buffer_index() const { return _buffer_index; }

const std::vector<std::uint8_t>& BlockBuffer512::get_buffer() const {
  return buffer;
}
}  // namespace crypto
