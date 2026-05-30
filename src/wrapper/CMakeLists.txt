# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# OPTIONAL "single layer" convenience wrapper over the MsQuic public API.
#
# This subdirectory is only added when QUIC_BUILD_WRAPPER=ON (see the top-level
# CMakeLists.txt). It is OFF by default so it never disturbs the normal msquic
# build. Building it requires the msquic library, which in turn needs the TLS
# submodule (quictls/OpenSSL) to be present and built -- defer the actual
# build/run to the rtxserver step.

# The wrapper itself: a thin static library exposing the C-friendly surface.
add_library(quic_wrapper STATIC quic.cpp)

# 'inc' provides the MsQuic public headers (msquic.h etc.); 'msquic' is the
# core library that the wrapper forwards into.
target_link_libraries(quic_wrapper PUBLIC inc)
target_link_libraries(quic_wrapper PRIVATE msquic warnings)

if (BUILD_SHARED_LIBS)
    target_link_libraries(quic_wrapper PRIVATE msquic_platform)
endif()

target_include_directories(quic_wrapper PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set_property(TARGET quic_wrapper PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}wrapper")

# The self-contained 127.0.0.1 loopback echo demo.
add_executable(quic_wrapper_echo example/echo.c)
target_link_libraries(quic_wrapper_echo quic_wrapper inc msquic logging base_link)

if (BUILD_SHARED_LIBS)
    target_link_libraries(quic_wrapper_echo msquic_platform)
endif()

if (NOT WIN32)
    find_package(Threads REQUIRED)
    target_link_libraries(quic_wrapper_echo Threads::Threads)
endif()

set_property(TARGET quic_wrapper_echo PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}wrapper")
set_property(TARGET quic_wrapper_echo APPEND PROPERTY BUILD_RPATH "$ORIGIN")
