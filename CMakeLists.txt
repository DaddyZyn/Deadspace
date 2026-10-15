cmake_minimum_required(VERSION 3.20)
project(deadspace VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /EHsc)
endif()

include_directories(include)

set(DS_CORE_SOURCES
    src/image.cpp
    src/scan.cpp
    src/bridge.cpp
    src/runtime.cpp
)

# core CLI tool
add_executable(deadspace
    src/entry.cpp
    ${DS_CORE_SOURCES}
)

# test target dummy DLL
add_library(test_target SHARED
    tests/test_target.cpp
)

# test runner suite
add_executable(test_runner
    tests/test_runner.cpp
    ${DS_CORE_SOURCES}
)

# live in-process test target
add_executable(live_test
    tests/live_test.cpp
    ${DS_CORE_SOURCES}
)
if(MSVC)
    set_target_properties(live_test PROPERTIES LINK_FLAGS "/IGNORE:4078")
endif()

# in-process self-test with live unhooking
add_executable(self_test
    tests/self_test.cpp
    ${DS_CORE_SOURCES}
)
if(MSVC)
    set_target_properties(self_test PROPERTIES LINK_FLAGS "/IGNORE:4078")
endif()

# system dll cave scan & multi-hook benchmark
add_executable(showcase
    tests/showcase.cpp
    ${DS_CORE_SOURCES}
)
if(MSVC)
    set_target_properties(showcase PROPERTIES LINK_FLAGS "/IGNORE:4078")
endif()



