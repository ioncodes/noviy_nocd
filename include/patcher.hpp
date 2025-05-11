#pragma once

#include <memory>
#include <filesystem>
#include <unordered_map>
#include <vector>
#include <ranges>
#include <print>
#include <array>
#include <functional>

#include <Zydis/Zydis.h>
#include <pe-parse/parse.h>

#include <utils.hpp>
#include <pattern.hpp>
#include <disasm.hpp>

using namespace noviy;
using namespace peparse;

namespace fs = std::filesystem;

namespace noviy {
class Patcher {
  private:
    std::unique_ptr<parsed_pe, std::function<void(parsed_pe*)>> parser_;
    fs::path binary_path_;
    std::vector<std::uint8_t> buffer_;
    ZyanUSize image_base_ = 0x00400000;

    auto build_iat_lookup_table() -> std::unordered_map<std::uint64_t, std::string>;
    auto remove_relocation_entry(std::size_t offset_to_remove);

  public:
    Patcher(fs::path binary_path) : binary_path_(std::move(binary_path)), buffer_(read_file(binary_path_)) {
        parser_ = std::unique_ptr<parsed_pe, std::function<void(parsed_pe*)>>(
            ParsePEFromBuffer(makeBufferFromPointer(buffer_.data(), buffer_.size())), DestructParsedPE);
        image_base_ = parser_->peHeader.nt.OptionalHeader.ImageBase;
    }
    virtual ~Patcher() = default;

    auto patch_initial_cd_checks() -> void;
    auto patch_checksum_checks() -> void;
    auto patch_deco_checks() -> void;

    auto save() -> void {
        fs::path backup_path = binary_path_;
        fs::path extension = backup_path.extension();
        backup_path.replace_filename(binary_path_.stem().string() + ".nocd" + extension.string());
        std::print("Writing crack to: {}\n", backup_path.string());
        write_file(backup_path, buffer_);
    }

    static auto patch_all(const fs::path& binary_path) {
        auto patcher = Patcher(binary_path);

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
    }

    [[nodiscard]] auto image_base() const -> std::uint32_t { return image_base_; }
    [[nodiscard]] auto path() const -> std::string { return binary_path_.string(); }
    [[nodiscard]] auto buffer_size() const -> std::size_t { return buffer_.size(); }
};
}  // namespace noviy