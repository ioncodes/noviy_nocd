cmake_minimum_required(VERSION 3.30)
project(noviy_nocd)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)

# Set pe-parse to build as a static library instead of a DLL
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build Shared Libraries" FORCE)

add_subdirectory("deps/zydis")
add_subdirectory("deps/pe-parse")

add_executable(noviy_nocd src/disasm.cpp src/patcher.cpp src/main.cpp)

target_include_directories(noviy_nocd PRIVATE include/)

target_link_libraries(noviy_nocd PRIVATE "Zydis")
target_link_libraries(noviy_nocd PRIVATE "pe-parse")