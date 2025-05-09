#include <disasm.hpp>

#include <print>
#include <iostream>

using namespace noviy;

auto ZydisInstruction::disassemble(const std::vector<std::uint8_t>& data, const ZyanUSize offset,
                                   const ZyanU64 runtime_address) -> std::optional<ZydisInstruction> {
    if (offset >= data.size()) {
        return std::nullopt;
    }

    ZydisDisassembledInstruction instruction;
    const bool success = ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_COMPAT_32, runtime_address,
                                                            &data[offset], data.size() - offset, &instruction));

    if (!success) {
        return std::nullopt;
    }

    return ZydisInstruction{instruction, runtime_address, offset};
}

auto ZydisInstruction::disassemble_until(const std::vector<std::uint8_t>& data, const std::size_t start_offset,
                                         const ZyanU64 runtime_address,
                                         const std::function<bool(const ZydisInstruction&)>& predicate,
                                         const std::size_t max_instructions) -> std::optional<ZydisInstruction> {
    std::size_t instr_offset = start_offset;
    std::size_t count = 0;

    while (count < max_instructions) {
        auto instr = ZydisInstruction::disassemble(data, instr_offset, runtime_address + (instr_offset - start_offset));
        if (!instr) {
            std::print(std::cerr, "Failed to disassemble instruction at offset: {:x}\n", instr_offset);
            break;
        }

        std::print("{}\n", instr.value());

        if (predicate(*instr)) {
            return instr;
        }

        instr_offset += instr->size();
        count++;
    }

    return std::nullopt;
}