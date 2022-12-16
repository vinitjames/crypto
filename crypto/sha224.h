#include "sha256.h"

namespace crypto {

class SHA224 {
 public:
  std::vector<std::uint32_t> get_digest(const std::string& message);

 private:
  SHA256 sha256{{0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31,
                 0x68581511, 0x64f98fa7, 0xbefa4fa4}};
};
}  // namespace crypto
