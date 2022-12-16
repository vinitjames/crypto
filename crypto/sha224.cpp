#include "sha224.h"

namespace crypto {
std::vector<std::uint32_t> SHA224::get_digest(const std::string& message) {
  std::vector<std::uint32_t> digest = sha256.get_digest(message);
  digest.pop_back();
  return digest;
}

}  // namespace crypto
