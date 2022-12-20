#pragma once

#include "sha512.h"

namespace crypto {

class SHA384 {
 public:
  std::vector<std::uint64_t> get_digest(const std::string& message);

 private:
  SHA512 sha512{{0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
                 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
                 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4}};
};
}  // namespace crypto
