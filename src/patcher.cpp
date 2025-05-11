#include <patcher.hpp>

#include <print>
#include <iostream>
#include <cstring>

using namespace noviy;

auto Patcher::build_iat_lookup_table() -> std::unordered_map<std::uint64_t, std::string> {
    std::unordered_map<std::uint64_t, std::string> iat_lookup_table;

    auto callback = [](void* context, const VA& addr, const std::string& module, const std::string& symbol) -> int {
        auto* table = static_cast<decltype(iat_lookup_table)*>(context);

        static constexpr std::array<const char*, 2> CD_CHECK_BYPASS = {
            "GetLogicalDriveStringsA",  // Lego Racers 2
            "GetLogicalDrives"          // Lego Rock Raiders / Lego Alpha Team
        };

        if (std::ranges::find(CD_CHECK_BYPASS, symbol) != CD_CHECK_BYPASS.end()) {
            std::print("Found {} in IAT: 0x{:x}\n", symbol, addr);
            (*table)[addr] = symbol;
        }

        return 0;
    };

    IterImpVAString(parser_.get(), callback, &iat_lookup_table);

    return iat_lookup_table;
}

auto Patcher::remove_relocation_entry(std::size_t offset_to_remove) {
    struct SectionInfo {
        std::uint64_t reloc_section_offset;
        std::uint64_t reloc_section_rva;
        std::uint32_t reloc_section_size;
    } section_info = {0, 0, 0};

    auto section_callback = [](void* cbd, const VA& base, const std::string& name, const image_section_header& sec,
                               const bounded_buffer* data) -> int {
        auto* info = static_cast<SectionInfo*>(cbd);

        if (name == ".reloc") {
            info->reloc_section_offset = sec.PointerToRawData;
            info->reloc_section_rva = sec.VirtualAddress;
            info->reloc_section_size = sec.SizeOfRawData;
            return 1;
        }

        return 0;
    };

    // iterate through sections to find the relocation section
    IterSec(parser_.get(), section_callback, &section_info);

    std::uint64_t reloc_section_offset = section_info.reloc_section_offset;
    std::uint64_t reloc_section_rva = section_info.reloc_section_rva;
    std::uint32_t reloc_section_size = section_info.reloc_section_size;

    if (reloc_section_offset == 0) {
        std::print(std::cerr, "No relocation section found\n");
        return;
    }

    // calculate the RVA of the offset we want to remove
    std::uint32_t target_rva = 0;

    struct TargetInfo {
        std::size_t offset_to_remove;
        std::uint32_t target_rva;
    } target_info = {offset_to_remove, 0};

    auto target_callback = [](void* cbd, const VA& base, const std::string& name, const image_section_header& sec,
                              const bounded_buffer* data) -> int {
        auto* info = static_cast<TargetInfo*>(cbd);

        if (info->offset_to_remove >= sec.PointerToRawData &&
            info->offset_to_remove < sec.PointerToRawData + sec.SizeOfRawData) {
            info->target_rva = sec.VirtualAddress + (info->offset_to_remove - sec.PointerToRawData);
            return 1;
        }

        return 0;
    };

    IterSec(parser_.get(), target_callback, &target_info);
    target_rva = target_info.target_rva;

    if (target_rva == 0) {
        std::print(std::cerr, "Could not find section containing the offset {}\n", offset_to_remove);
        return;
    }

    std::print("Searching for relocation entry for RVA: 0x{:x}\n", target_rva);

    std::size_t reloc_ptr = reloc_section_offset;
    while (reloc_ptr < reloc_section_offset + reloc_section_size) {
        if (reloc_ptr + 8 > buffer_.size()) {
            break;
        }

        std::uint32_t page_rva = *reinterpret_cast<std::uint32_t*>(&buffer_[reloc_ptr]);
        std::uint32_t block_size = *reinterpret_cast<std::uint32_t*>(&buffer_[reloc_ptr + 4]);

        if (block_size == 0 || block_size > reloc_section_size) {
            break;
        }

        // check if our target could be in this block
        if (target_rva >= page_rva && target_rva < page_rva + 0x1000) {
            std::print(
                "Found potential relocation block at offset 0x{:x}, page RVA: "
                "0x{:x}, size: {}\n",
                reloc_ptr, page_rva, block_size);

            std::size_t entries_start = reloc_ptr + 8;
            std::size_t entries_end = reloc_ptr + block_size;

            for (std::size_t entry_ptr = entries_start; entry_ptr < entries_end; entry_ptr += 2) {
                if (entry_ptr + 2 > buffer_.size()) {
                    break;
                }

                std::uint16_t entry = *reinterpret_cast<std::uint16_t*>(&buffer_[entry_ptr]);
                std::uint16_t offset = entry & 0xFFF;
                std::uint32_t entry_rva = page_rva + offset;

                // check if this is our target
                if (entry_rva == target_rva || entry_rva == target_rva + 1 || entry_rva == target_rva + 2 ||
                    entry_rva == target_rva + 3) {
                    std::print("Found relocation entry at offset 0x{:x}, RVA: 0x{:x}\n", entry_ptr, entry_rva);

                    // zero the relocation entry
                    buffer_[entry_ptr] = 0;
                    buffer_[entry_ptr + 1] = 0;

                    std::print("Removed relocation entry\n");
                }
            }
        }

        reloc_ptr += block_size;
    }
}

auto Patcher::patch_checksum_checks() -> void {
    const auto pattern = pattern_t{0x03, 0x06, 0x46, 0x49, 0x75, 0xFA};

    // find "sub [esp+10h+var_10], eax"
    const auto predicate = [](const ZydisInstruction& instr) {
        return instr.backing.info.mnemonic == ZYDIS_MNEMONIC_SUB && instr.backing.info.operand_count >= 2 &&
               instr.backing.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
               instr.backing.operands[0].mem.base == ZYDIS_REGISTER_ESP &&
               instr.backing.operands[1].reg.value == ZYDIS_REGISTER_EAX;
    };

    for (const auto& offset : Pattern::find_all(buffer_, pattern)) {
        std::print("Checksum loop found at: 0x{:x}\n", image_base_ + offset);

        auto instr = ZydisInstruction::disassemble_until(buffer_, offset, image_base_ + offset, predicate);
        if (!instr) {
            std::print(std::cerr, "Could not find tamper instruction\n");
            continue;
        }

        std::print("Found tamper instruction at: 0x{:x}\n", image_base_ + instr->offset);

        // replace with NOPs
        std::memset(&buffer_[instr->offset], 0x90, 3);
    }
}

auto Patcher::patch_deco_checks() -> void {
    constexpr auto PROGRESSIVE_DECOMPRESS_OFFSET = 20;

    // clang-format off
    const auto pattern = pattern_t{
        0xBA, {}, 0x00, 0x00, 0x00,    // mov edx, trackNumber
        0x52,                          // push edx
        0x33, 0xC0,                    // xor eax, eax
        0xA0, {}, {}, {}, {},          // mov al, driveLetter
        0x50,                          // push eax
    };
    // clang-format on

    const auto cmp_predicate = [](const ZydisInstruction& instr) -> bool {
        // check if instruction is a CMP with immediate value and memory operand
        // using EBP
        return instr.backing.info.mnemonic == ZYDIS_MNEMONIC_CMP && instr.backing.info.operand_count >= 2 &&
               instr.backing.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
               instr.backing.operands[0].mem.base == ZYDIS_REGISTER_EBP &&
               instr.backing.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
    };

    for (const auto& image_offset : Pattern::find_all(buffer_, pattern)) {
        const std::size_t virtual_address = image_base_ + image_offset;
        const std::size_t drm_address = virtual_address + PROGRESSIVE_DECOMPRESS_OFFSET;

        std::print("Prologue to ProgressiveDecompress_24 found at: 0x{:x}\n", virtual_address);
        std::print("Setup for ProgressiveDecompress_24 at: 0x{:x}\n", drm_address);

        auto cmp_instr = ZydisInstruction::disassemble_until(buffer_, image_offset, virtual_address, cmp_predicate);
        if (!cmp_instr) {
            std::print(std::cerr, "Couldn't find the magic CMP instruction\n");
            continue;
        }

        auto magic_value = static_cast<std::uint32_t>(cmp_instr->backing.operands[1].imm.value.u);
        std::print("Magic value: 0x{:x}\n", magic_value);

        // point to the instruction before the "push edx, ProgressiveDecompress_24"
        const std::size_t patch_offset = image_offset + PROGRESSIVE_DECOMPRESS_OFFSET - 1;

        // ProgressiveDecompress_24 cleans up the stack ("retn 8")
        // so we need to incorporate that into our patch
        // we'll do this by overwriting the following sequence

        // .text:1002B4E6 52              push    edx
        // .text:1002B4E7 BA 76 49 07 10  mov     edx, offset
        // ProgressiveDecompress_24 .text:1002B4EC 52              push    edx
        // .text:1002B4ED C3              retn

        // into the following sequence

        // 023DB4E6 | 83C4 08                  | add esp,8
        // 023DB4E9 | B8 2E0A4B00              | mov eax,MAGIC

        // this also gets rid of the push; ret indirection which is fine

        // 83 C4 08 = ADD ESP, 8
        buffer_[patch_offset + 0] = 0x83;
        buffer_[patch_offset + 1] = 0xC4;
        buffer_[patch_offset + 2] = 0x08;

        // B8 xx xx xx xx = MOV EAX, imm32
        buffer_[patch_offset + 3] = 0xB8;
        buffer_[patch_offset + 4] = static_cast<std::uint8_t>(magic_value & 0xFF);
        buffer_[patch_offset + 5] = static_cast<std::uint8_t>((magic_value >> 8) & 0xFF);
        buffer_[patch_offset + 6] = static_cast<std::uint8_t>((magic_value >> 16) & 0xFF);
        buffer_[patch_offset + 7] = static_cast<std::uint8_t>((magic_value >> 24) & 0xFF);

        std::print("Patched ProgressiveDecompress_24 setup:\n");
        ZydisInstruction::disassemble_until(buffer_, image_offset, virtual_address, cmp_predicate);

        // remove the relocation entry for the ProgressiveDecompress_24 call
        std::print("\n*** Removing relocation entries for ProgressiveDecompress_24 ***\n");
        remove_relocation_entry(patch_offset + 1);  // address bytes start at offset+1
        std::print("\n");
    }
}

auto Patcher::patch_initial_cd_checks() -> void {
    const auto iat_lut = build_iat_lookup_table();

    int offset = 0;
    while (offset < static_cast<int>(buffer_.size())) {
        // we're just bruteforcing through the file, expect errors
        auto instr = ZydisInstruction::disassemble(buffer_, offset, image_base_ + offset);
        if (!instr) {
            offset++;
            continue;
        }

        // skip if not call instruction
        if (instr->backing.info.mnemonic != ZYDIS_MNEMONIC_CALL ||
            instr->backing.operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY) {
            offset++;
            continue;
        }

        // check if this is a call to a CD-check function
        const auto iat_address = instr->backing.operands[0].mem.disp.value;
        if (!iat_lut.contains(iat_address)) {
            offset++;
            continue;
        }

        std::print("Found call to {} at 0x{:x}\n", iat_lut.at(iat_address), image_base_ + offset);

        // find next JCC
        const auto jcc_predicate = [](const ZydisInstruction& instr) {
            return instr.backing.info.mnemonic == ZYDIS_MNEMONIC_JZ ||
                   instr.backing.info.mnemonic == ZYDIS_MNEMONIC_JBE;
        };

        auto jcc_instr = ZydisInstruction::disassemble_until(buffer_, offset, image_base_ + offset, jcc_predicate);
        if (!jcc_instr) {
            offset++;
            continue;
        }

        std::print("Found JCC at 0x{:x}\n", image_base_ + jcc_instr->offset);

        const auto invert_jz = [](std::vector<std::uint8_t>& data, const ZyanUSize offset) {
            if (data[offset] == 0x74) {
                data[offset] = 0x75;  // JNZ short
            } else if (data[offset] == 0x0F && data[offset + 1] == 0x84) {
                data[offset + 1] = 0x85;  // JNZ far
            }
        };

        const auto invert_jbe = [](std::vector<std::uint8_t>& data, const ZyanUSize offset) {
            if (data[offset] == 0x76) {
                data[offset] = 0x77;  // JNBE short
            } else if (data[offset] == 0x0F && data[offset + 1] == 0x86) {
                data[offset + 1] = 0x87;  // JNBE far
            }
        };

        // invert JCC
        switch (jcc_instr->backing.info.mnemonic) {
            case ZYDIS_MNEMONIC_JZ:
                invert_jz(buffer_, jcc_instr->offset);
                break;
            case ZYDIS_MNEMONIC_JBE:
                invert_jbe(buffer_, jcc_instr->offset);
                break;
            default:
                std::print(std::cerr, "Unknown JCC at 0x{:x}\n", image_base_ + jcc_instr->offset);
                return;
        }

        // dump to confirm patch
        ZydisInstruction::disassemble_until(buffer_, offset, image_base_ + offset, [](const ZydisInstruction& instr) {
            return instr.backing.info.mnemonic == ZYDIS_MNEMONIC_JNZ ||
                   instr.backing.info.mnemonic == ZYDIS_MNEMONIC_JNBE;
        });

        return;
    }

    std::print(std::cerr, "Could not find CD TOC check to patch\n");
}