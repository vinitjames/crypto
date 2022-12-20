#include "sha512_256.h"
#include <iostream>
namespace crypto {
	std::vector<std::uint64_t> SHA512_256::get_digest(const std::string& message) {
		std::vector<std::uint64_t> digest = sha512.get_digest(message);
		std::cout << digest.size() << std::endl;
		return std::vector<std::uint64_t>{ digest.begin(), digest.end() - 4 };
	}

}  // namespace crypto
