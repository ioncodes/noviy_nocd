#include <print>
#include <iostream>

#include <patcher.hpp>

using namespace noviy;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::print(std::cerr, "Usage: {} <path_to_executable>\n", argv[0]);
        return 1;
    }

    Patcher::patch_all(argv[1]);
    
    return 0;
}
