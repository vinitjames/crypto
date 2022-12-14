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
