#include "sha512_224.h"
#include <iostream>
namespace crypto {
	std::vector<std::uint64_t> SHA512_224::get_digest(const std::string& message) {
		std::vector<std::uint64_t> digest = sha512.get_digest(message);
		std::cout << digest.size() << std::endl;
		digest = std::vector<std::uint64_t>{digest.begin(), digest.end() - 4};
		std::cout << digest.size()<<std::endl;
		digest.back() &= 0xFFFFFFFF00000000;
		return digest;
	}

}  // namespace crypto

