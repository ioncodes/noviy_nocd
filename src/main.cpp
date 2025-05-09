#include <filesystem>

#include <utils.hpp>
#include <patcher.hpp>

using namespace peparse;
using namespace noviy;

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    auto patcher = Patcher(fs::path{argv[1]});

    std::print("Executable: {}\n", patcher.path());
    std::print("Size: {} bytes\n", patcher.buffer_size());
    std::print("Image base: 0x{:x}\n", patcher.image_base());

    std::print("\n*** Patching initial CD checks ***\n");
    patcher.patch_initial_cd_checks();

    std::print("\n*** Patching checksum checks ***\n");
    patcher.patch_checksum_checks();

    std::print("\n*** Patching ProgressiveDecompress_24 CD TOC checks ***\n");
    patcher.patch_deco_checks();

    patcher.save();

    return 0;
}
