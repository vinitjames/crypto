#pragma once

#include "sha512.h"

namespace crypto {

class SHA512_224 {
 public:
  std::vector<std::uint64_t> get_digest(const std::string& message);

 private:
  SHA512 sha512{{0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82,
                 0x679DD514582F9FCF, 0x0F6D2B697BD44DA8, 0x77E36F7304C48942,
                 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1}};
};
}  // namespace crypto
