#pragma once

#include <cstdint>

namespace crypto {
namespace util {

	
	std::uint32_t ROTL(std::uint32_t value, std::uint8_t pos);

	std::uint32_t ROTR(std::uint32_t value, std::uint8_t pos);

	std::uint32_t SHR(std::uint32_t value, std::uint8_t pos);

	std::uint64_t ROTL(std::uint64_t value, std::uint8_t pos);

	std::uint64_t ROTR(std::uint64_t value, std::uint8_t pos);

	std::uint64_t SHR(std::uint64_t value, std::uint8_t pos);

}  // namespace util
}  // namespace crypto
