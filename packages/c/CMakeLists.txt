cmake_minimum_required(VERSION 3.14)
project(lcore-sdk-c VERSION 0.1.0 LANGUAGES C CXX)

# Platform options (mutually exclusive for HTTP transport)
option(LCORE_USE_CURL "Enable HTTP support via libcurl (Linux/macOS)" ON)
option(LCORE_PLATFORM_ESP32 "Build for ESP32 with ESP-IDF" OFF)
option(LCORE_PLATFORM_ARDUINO "Build for Arduino" OFF)
option(LCORE_BUILD_EXAMPLES "Build example programs" ON)

# Find MbedTLS
find_package(MbedTLS QUIET)
if(NOT MbedTLS_FOUND)
    # Try pkg-config first
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(MBEDTLS QUIET mbedtls mbedcrypto mbedx509)
    endif()

    # Fallback: Manual detection for Debian/Ubuntu where pkg-config files are missing
    if(NOT MBEDTLS_FOUND)
        find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h PATHS /usr/include /usr/local/include)
        find_library(MBEDTLS_LIBRARY mbedtls PATHS /usr/lib /usr/lib/aarch64-linux-gnu /usr/lib/x86_64-linux-gnu)
        find_library(MBEDCRYPTO_LIBRARY mbedcrypto PATHS /usr/lib /usr/lib/aarch64-linux-gnu /usr/lib/x86_64-linux-gnu)
        find_library(MBEDX509_LIBRARY mbedx509 PATHS /usr/lib /usr/lib/aarch64-linux-gnu /usr/lib/x86_64-linux-gnu)

        if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIBRARY AND MBEDCRYPTO_LIBRARY AND MBEDX509_LIBRARY)
            set(MBEDTLS_FOUND TRUE)
            set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
            set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARY} ${MBEDCRYPTO_LIBRARY} ${MBEDX509_LIBRARY})
            message(STATUS "Found MbedTLS (manual): ${MBEDTLS_LIBRARIES}")
        else()
            message(FATAL_ERROR "MbedTLS not found. Install libmbedtls-dev")
        endif()
    endif()
endif()

# Find libcurl if enabled
if(LCORE_USE_CURL)
    find_package(CURL REQUIRED)
endif()

# Library sources
set(LCORE_SOURCES src/lcore.c)

# Add platform-specific transport
if(LCORE_PLATFORM_ESP32)
    list(APPEND LCORE_SOURCES src/transport_esp32.c)
elseif(LCORE_PLATFORM_ARDUINO)
    list(APPEND LCORE_SOURCES src/transport_arduino.cpp)
endif()

add_library(lcore STATIC ${LCORE_SOURCES})
target_include_directories(lcore PUBLIC include)

# Link MbedTLS
if(MbedTLS_FOUND)
    target_link_libraries(lcore PRIVATE MbedTLS::mbedtls MbedTLS::mbedcrypto)
else()
    target_include_directories(lcore PRIVATE ${MBEDTLS_INCLUDE_DIRS})
    target_link_libraries(lcore PRIVATE ${MBEDTLS_LIBRARIES})
endif()

# Platform-specific compile definitions and linking
if(LCORE_PLATFORM_ESP32)
    target_compile_definitions(lcore PRIVATE LCORE_PLATFORM_ESP32)
    # ESP-IDF handles linking via component system
elseif(LCORE_PLATFORM_ARDUINO)
    target_compile_definitions(lcore PRIVATE LCORE_PLATFORM_ARDUINO)
    # Arduino IDE handles linking
elseif(LCORE_USE_CURL)
    target_compile_definitions(lcore PRIVATE LCORE_USE_CURL)
    target_link_libraries(lcore PRIVATE CURL::libcurl)
endif()

# Examples
if(LCORE_BUILD_EXAMPLES)
    add_executable(example_submit examples/submit.c)
    target_link_libraries(example_submit PRIVATE lcore)
endif()

# Tests
option(LCORE_BUILD_TESTS "Build tests" ON)
if(LCORE_BUILD_TESTS)
    enable_testing()
    add_executable(test_lcore tests/test_lcore.c)
    target_link_libraries(test_lcore PRIVATE lcore)
    add_test(NAME lcore_tests COMMAND test_lcore)
endif()

# Install
install(TARGETS lcore ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
