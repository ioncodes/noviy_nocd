#pragma once

#include <vector>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

namespace noviy {
static auto read_file(const fs::path& path) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> data;
    std::ifstream file(path, std::ios::binary);

    file.seekg(0, std::ios::end);
    data.resize(file.tellg());
    file.seekg(0, std::ios::beg);

    file.read(reinterpret_cast<char*>(data.data()), data.size());

    return data;
}

static auto write_file(const fs::path& path, const std::vector<std::uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}
}  // namespace noviy