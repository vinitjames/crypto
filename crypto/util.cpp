#include "util.h"

std::uint32_t crypto::util::ROTL(std::uint32_t value, std::uint8_t pos) {
  return (value << pos) | (value >> (32 - pos));
}

std::uint32_t crypto::util::ROTR(std::uint32_t value, std::uint8_t pos) {
  return (value >> pos) | (value << (32 - pos));
}

std::uint32_t crypto::util::SHR(std::uint32_t value, std::uint8_t pos) {
  return value >> pos;
}

std::uint64_t crypto::util::ROTL(std::uint64_t value, std::uint8_t pos) {
	return (value << pos) | (value >> (64 - pos));
}

std::uint64_t crypto::util::ROTR(std::uint64_t value, std::uint8_t pos) {
	return (value >> pos) | (value << (64 - pos));
}

std::uint64_t crypto::util::SHR(std::uint64_t value, std::uint8_t pos) {
	return value >> pos;
}
