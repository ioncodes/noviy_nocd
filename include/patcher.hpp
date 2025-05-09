#pragma once

#include <memory>
#include <filesystem>
#include <unordered_map>
#include <vector>
#include <ranges>
#include <print>
#include <array>

#include <Zydis/Zydis.h>
#include <pe-parse/parse.h>

#include <utils.hpp>
#include <pattern.hpp>
#include <disasm.hpp>

using namespace noviy;
using namespace peparse;

namespace fs = std::filesystem;

namespace noviy {
struct PeParseDeleter {
    void operator()(parsed_pe* res) const {
        if (res) {
            DestructParsedPE(res);
            delete res;
        }
    }
};

class Patcher {
  private:
    std::unique_ptr<parsed_pe, PeParseDeleter> parser_;
    fs::path binary_path_;
    std::vector<std::uint8_t> buffer_;
    ZyanUSize image_base_ = 0x00400000;

    auto build_iat_lookup_table() -> std::unordered_map<std::uint64_t, std::string>;
    auto remove_relocation_entry(std::size_t offset_to_remove);

  public:
    Patcher(fs::path binary_path) : binary_path_(std::move(binary_path)), buffer_(read_file(binary_path_)) {
        parser_ = std::unique_ptr<parsed_pe, PeParseDeleter>(
            ParsePEFromBuffer(makeBufferFromPointer(buffer_.data(), buffer_.size())));
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

    [[nodiscard]] auto image_base() const -> std::uint32_t { return image_base_; }
    [[nodiscard]] auto path() const -> std::string { return binary_path_.string(); }
    [[nodiscard]] auto buffer_size() const -> std::size_t { return buffer_.size(); }
};
}  // namespace noviy