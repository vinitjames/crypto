// crypto.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <iostream>
#include <functional>

namespace crypto {
	class SHA1 {
	public:
		std::vector < std::uint32_t> get_digest(const std::string& message);
	private:
		class Hash {
			std::vector<std::function<std::uint32_t(std::uint32_t,
				std::uint32_t,
				std::uint32_t)>>
				functors = { 
				[](std::uint32_t x, std::uint32_t y, std::uint32_t z) 
					{return (x & y) ^ (~x & z); },
				[](std::uint32_t x, std::uint32_t y, std::uint32_t z)
					{return x^y^z; },
				[](std::uint32_t x, std::uint32_t y, std::uint32_t z)
					{return (x & y) ^ (x & z) ^(x&y); }

			};
			std::vector<std::uint32_t> W;
			static constexpr std::array<std::uint32_t, 4> _k{
			0x5a827999,
			0x6ed9eba1,
			0x8f1bbcdc,
			0xca62c1d6 };

			std::array<std::uint32_t, 5> digest{
				0x67452301,
				0xefcdab89,
				0x98badcfe,
				0x10325476,
				0xc3d2e1f0
			};
			std::array<std::uint32_t, 5> working_var{ digest };
		public:
			void hash_block(const std::vector<std::uint8_t> block);
			std::vector<std::uint32_t> get_digest();
		};
		void update_block_buffer(const std::string& message, std::size_t pos);
		void clear_block_buffer();
		void append_length_to_block_buffer(std::uint64_t size);
		std::vector<std::uint8_t> block_buffer;
		std::size_t block_buffer_counter;
		
	};
}

// TODO: Reference additional headers your program requires here.
