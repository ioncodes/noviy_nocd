#pragma once

#include <optional>
#include <vector>
#include <format>
#include <functional>

#include <Zydis/Zydis.h>

namespace noviy {
struct ZydisInstruction {
    ZydisDisassembledInstruction backing;
    ZyanU64 runtime_address;
    ZyanUSize offset;

    [[nodiscard]] std::size_t size() const { return backing.info.length; }

    static auto disassemble(const std::vector<std::uint8_t>& data, const ZyanUSize offset,
                            const ZyanU64 runtime_address) -> std::optional<ZydisInstruction>;
    static auto disassemble_until(const std::vector<std::uint8_t>& data, const std::size_t start_offset,
                                  const ZyanU64 runtime_address,
                                  const std::function<bool(const ZydisInstruction&)>& predicate,
                                  const std::size_t max_instructions = 200) -> std::optional<ZydisInstruction>;
};
}  // namespace noviy

template <>
struct std::formatter<noviy::ZydisInstruction> {
    constexpr auto parse(std::format_parse_context& ctx) { return ctx.begin(); }

    auto format(const noviy::ZydisInstruction& instr, std::format_context& ctx) const {
        return std::format_to(ctx.out(), "{:016X}  {}", instr.backing.runtime_address, instr.backing.text);
    }
};