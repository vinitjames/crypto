
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace crypto {
class SHA256 {
 public:
  SHA256();
  std::vector<std::uint32_t> get_digest(const std::string& message);

 private:
  class BlockHash {
    std::array<std::uint32_t, 64> W;

    std::array<std::uint32_t, 8> digest{0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                        0xa54ff53a, 0x510e527f, 0x9b05688c,
                                        0x1f83d9ab, 0x5be0cd19};

    std::array<std::uint32_t, 8> work_var{digest};

    static constexpr std::array<std::uint32_t, 64> K{
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    static std::uint32_t Ch(std::uint32_t x, std::uint32_t y, std::uint32_t z);
    static std::uint32_t Maj(std::uint32_t x, std::uint32_t y, std::uint32_t z);
    static std::uint32_t Ep0(std::uint32_t x);
    static std::uint32_t Ep1(std::uint32_t x);
    static std::uint32_t Sig0(std::uint32_t x);
    static std::uint32_t Sig1(std::uint32_t x);

   public:
    void operator()(const std::vector<std::uint8_t>& block);
    std::vector<std::uint32_t> get_digest() const;
  };

  void update_block_buffer(const std::string& message, std::size_t pos);
  void clear_block_buffer();
  void append_length_to_block_buffer(std::uint64_t size);
  std::vector<std::uint8_t> block_buffer;
  std::size_t block_buffer_index = 0;
};
}  // namespace crypto
