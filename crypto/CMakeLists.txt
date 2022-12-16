# CMakeList.txt : CMake project for crypto, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.
add_executable (crypto "sha1.cpp" "sha1.h" "sha256.h" "sha256.cpp" "util.cpp" "block_buffer.h" "block_buffer.cpp" "sha224.h" "sha224.cpp")

# TODO: Add tests and install targets if needed.
