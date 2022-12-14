// crypto.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace crypto {
class SHA1 {
 public:
  SHA1();
  std::vector<std::uint32_t> get_digest(const std::string& message);

 private:
  class BlockHash {
    std::array<std::uint32_t, 80> W;

    std::array<std::uint32_t, 5> digest{0x67452301, 0xefcdab89, 0x98badcfe,
                                        0x10325476, 0xc3d2e1f0};

    std::array<std::uint32_t, 5> work_var{digest};

    static std::uint32_t f(std::uint32_t x, std::uint32_t y, std::uint32_t z,
                           std::size_t index);
    static std::uint32_t K(std::size_t index);

   public:
    void operator()(const std::vector<std::uint8_t>& block);
    std::vector<std::uint32_t> get_digest();
  };
  void update_block_buffer(const std::string& message, std::size_t pos);
  void clear_block_buffer();
  void append_length_to_block_buffer(std::uint64_t size);
  std::vector<std::uint8_t> block_buffer;
  std::size_t block_buffer_index = 0;
};
}  // namespace crypto

// TODO: Reference additional headers your program requires here.
