cmake_minimum_required(VERSION 3.10)
project(apex-cipher C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native -funroll-loops")

add_executable(apex-cipher
    main.c
    source/repl.c
    source/sbox.c
    source/keygen.c
    source/round_ops.c
    source/encrypt_decrypt.c
    source/cipher.c
    source/utils.c
    source/hash.c
    source/hmac.c
    source/crypto_context.c
)

target_include_directories(apex-cipher PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/source
)

#[[
# standard build command
cmake -S . -B build/ -DCMAKE_BUILD_TYPE=Release
cmake --build build/ --parallel
]]