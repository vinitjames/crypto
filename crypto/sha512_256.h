#pragma once

#include "sha512.h"

namespace crypto {

class SHA512_256 {
 public:
  std::vector<std::uint64_t> get_digest(const std::string& message);

 private:
  SHA512 sha512{{0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151,
                 0x963877195940EABD, 0x96283EE2A88EFFE3, 0xBE5E1E2553863992,
                 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2}};
};
}  // namespace crypto
