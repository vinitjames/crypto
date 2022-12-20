#include "sha384.h"

namespace crypto {
std::vector<std::uint64_t> SHA384::get_digest(const std::string& message) {
  std::vector<std::uint64_t> digest = sha512.get_digest(message);
  return std::vector<std::uint64_t>{digest.begin(), digest.end() - 2};
}

}  // namespace crypto
