cmake_minimum_required(VERSION 3.10)
project(apex-cipher C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native -funroll-loops")

add_executable(apex-cipher
    main.c
    source/core/cipher.c
    source/core/cipher_ops.c
    source/core/encrypt_decrypt.c
    source/core/round_ops.c
    source/core/sbox.c
    source/core/keygen.c
    source/core/hash.c
    source/core/hmac.c
    source/core/kdf.c
    source/core/crypto_context.c
    source/cli/args.c
    source/utils/utils.c
)

target_include_directories(apex-cipher PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/source/core
    ${CMAKE_CURRENT_SOURCE_DIR}/source/cli
    ${CMAKE_CURRENT_SOURCE_DIR}/source/utils
)

#[[
# standard build command
cmake -S . -B build/ -DCMAKE_BUILD_TYPE=Release
cmake --build build/ --parallel
]]