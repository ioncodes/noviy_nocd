#include <algorithm>
#include <array>
#include <cinttypes>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <optional>
#include <vector>
#include <format>
#include <print>
#include <unordered_map>

#include <Zydis/Zydis.h> 
#include <pe-parse/parse.h>

using namespace peparse;

namespace fs = std::filesystem;

static std::uint32_t g_image_base = 0x00400000;

struct ZydisInstruction
{
    ZydisDisassembledInstruction backing;
    ZyanU64 runtime_address;
    ZyanUSize offset;

    [[nodiscard]] std::size_t size() const
    {
        return backing.info.length;
    }

    static std::optional<ZydisInstruction> disassemble(const std::vector<std::uint8_t>& data, const ZyanUSize offset,
        const ZyanU64 runtime_address)
    {
        if (offset >= data.size())
        {
            return std::nullopt;
        }

        ZydisDisassembledInstruction instruction;
        const bool success = ZYAN_SUCCESS(ZydisDisassembleIntel(
            ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
            runtime_address,
            &data[offset],
            data.size() - offset,
            &instruction
        ));

        if (!success)
        {
            return std::nullopt;
        }

        return ZydisInstruction{ instruction, runtime_address, offset };
    }
};

template<>
struct std::formatter<ZydisInstruction>
{
    constexpr auto parse(std::format_parse_context& ctx)
    {
        return ctx.begin();
    }

    auto format(const ZydisInstruction& instr, std::format_context& ctx) const
    {
        return std::format_to(ctx.out(), "{:016X}  {}", instr.backing.runtime_address, instr.backing.text);
    }
};

std::optional<ZydisInstruction> disassemble_until(const std::vector<std::uint8_t>& data, const std::size_t start_offset,
    const ZyanU64 runtime_address,
    const std::function<bool(const ZydisInstruction&)>& predicate,
    const std::size_t max_instructions = 200)
{
    std::size_t instr_offset = start_offset;
    std::size_t count = 0;

    while (count < max_instructions)
    {
        auto instr = ZydisInstruction::disassemble(data, instr_offset, runtime_address + (instr_offset - start_offset));
        if (!instr)
        {
            std::print(std::cerr, "Failed to disassemble instruction at offset: {:x}\n", instr_offset);
            break;
        }

        std::print("{}\n", instr.value());

        if (predicate(*instr))
        {
            return instr;
        }

        instr_offset += instr->size();
        count++;
    }

    return std::nullopt;
}

std::vector<std::uint8_t> read_file(const fs::path& path)
{
    std::vector<std::uint8_t> data;
    std::ifstream file(path, std::ios::binary);

    file.seekg(0, std::ios::end);
    data.resize(file.tellg());
    file.seekg(0, std::ios::beg);

    file.read(reinterpret_cast<char*>(data.data()), data.size());

    return data;
}

void write_file(const fs::path& path, const std::vector<std::uint8_t>& data)
{
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}

std::unordered_map<std::uint64_t, std::string> build_iat_lookup_table(std::vector<std::uint8_t>& data)
{
    std::unordered_map<std::uint64_t, std::string> iat_lookup_table;

    const auto parser = ParsePEFromBuffer(makeBufferFromPointer(data.data(), data.size()));

    auto callback = [](void* context, const VA& addr, const std::string& module, const std::string& symbol) -> int
    {
        auto* table = static_cast<decltype(iat_lookup_table)*>(context);

        static constexpr std::array<const char*, 2> CD_CHECK_BYPASS = {
            "GetLogicalDriveStringsA", // Lego Racers 2
            "GetLogicalDrives"         // Lego Rock Raiders / Lego Alpha Team
        };

        if (std::ranges::find(CD_CHECK_BYPASS, symbol) != CD_CHECK_BYPASS.end())
        {
            std::print("Found {} in IAT: 0x{:x}\n", symbol, addr);
            (*table)[addr] = symbol;
        }

        return 0;
    };

    IterImpVAString(parser, callback, &iat_lookup_table);
    DestructParsedPE(parser);

    return iat_lookup_table;
}

void remove_relocation_entry(std::vector<std::uint8_t>& data, std::size_t offset_to_remove)
{
    const auto parser = ParsePEFromBuffer(makeBufferFromPointer(data.data(), data.size()));

    struct SectionInfo {
        std::uint64_t reloc_section_offset;
        std::uint64_t reloc_section_rva;
        std::uint32_t reloc_section_size;
    } section_info = { 0, 0, 0 };

    auto section_callback = [](void* cbd, const VA& base, const std::string& name, const image_section_header& sec, const bounded_buffer* data) -> int
    {
        auto* info = static_cast<SectionInfo*>(cbd);

        if (name == ".reloc")
        {
            info->reloc_section_offset = sec.PointerToRawData;
            info->reloc_section_rva = sec.VirtualAddress;
            info->reloc_section_size = sec.SizeOfRawData;
            return 1;
        }

        return 0;
    };

    // iterate through sections to find the relocation section
    IterSec(parser, section_callback, &section_info);

    std::uint64_t reloc_section_offset = section_info.reloc_section_offset;
    std::uint64_t reloc_section_rva = section_info.reloc_section_rva;
    std::uint32_t reloc_section_size = section_info.reloc_section_size;

    if (reloc_section_offset == 0)
    {
        std::print(std::cerr, "No relocation section found\n");
        DestructParsedPE(parser);
        return;
    }

    // calculate the RVA of the offset we want to remove
    std::uint32_t target_rva = 0;

    struct TargetInfo {
        std::size_t offset_to_remove;
        std::uint32_t target_rva;
    } target_info = { offset_to_remove, 0 };

    auto target_callback = [](void* cbd, const VA& base, const std::string& name, const image_section_header& sec, const bounded_buffer* data) -> int
    {
        auto* info = static_cast<TargetInfo*>(cbd);

        if (info->offset_to_remove >= sec.PointerToRawData &&
            info->offset_to_remove < sec.PointerToRawData + sec.SizeOfRawData)
        {
            info->target_rva = sec.VirtualAddress + (info->offset_to_remove - sec.PointerToRawData);
            return 1;
        }

        return 0;
    };

    IterSec(parser, target_callback, &target_info);
    target_rva = target_info.target_rva;

    if (target_rva == 0)
    {
        std::print(std::cerr, "Could not find section containing the offset {}\n", offset_to_remove);
        DestructParsedPE(parser);
        return;
    }

    std::print("Searching for relocation entry for RVA: 0x{:x}\n", target_rva);

    std::size_t reloc_ptr = reloc_section_offset;
    while (reloc_ptr < reloc_section_offset + reloc_section_size)
    {
        if (reloc_ptr + 8 > data.size())
        {
            break;
        }

        std::uint32_t page_rva = *reinterpret_cast<std::uint32_t*>(&data[reloc_ptr]);
        std::uint32_t block_size = *reinterpret_cast<std::uint32_t*>(&data[reloc_ptr + 4]);

        if (block_size == 0 || block_size > reloc_section_size)
        {
            break;
        }

        // check if our target could be in this block
        if (target_rva >= page_rva && target_rva < page_rva + 0x1000)
        {
            std::print("Found potential relocation block at offset 0x{:x}, page RVA: 0x{:x}, size: {}\n", reloc_ptr, page_rva, block_size);

            std::size_t entries_start = reloc_ptr + 8;
            std::size_t entries_end = reloc_ptr + block_size;

            for (std::size_t entry_ptr = entries_start; entry_ptr < entries_end; entry_ptr += 2)
            {
                if (entry_ptr + 2 > data.size())
                {
                    break;
                }

                std::uint16_t entry = *reinterpret_cast<std::uint16_t*>(&data[entry_ptr]);
                std::uint16_t offset = entry & 0xFFF;
                std::uint32_t entry_rva = page_rva + offset;

                // check if this is our target
                if (entry_rva == target_rva || entry_rva == target_rva + 1 || entry_rva == target_rva + 2 || entry_rva == target_rva + 3)
                {
                    std::print("Found relocation entry at offset 0x{:x}, RVA: 0x{:x}\n", entry_ptr, entry_rva);

                    // zero the relocation entry
                    data[entry_ptr] = 0;
                    data[entry_ptr + 1] = 0;

                    std::print("Removed relocation entry\n");
                }
            }
        }

        reloc_ptr += block_size;
    }

    DestructParsedPE(parser);
}

std::vector<std::size_t> find_patterns(const std::vector<std::uint8_t>& data,
    const std::vector<std::optional<std::uint8_t>>& pattern)
{
    std::vector<std::size_t> results;

    auto predicate = [](const std::uint8_t& x, const std::optional<std::uint8_t>& y)
    {
        return !y.has_value() || (y.has_value() && x == y.value());
    };

    auto it = data.begin();
    while (it != data.end())
    {
        auto match_result = std::ranges::search(std::ranges::subrange(it, data.end()),
            std::ranges::subrange(pattern.begin(), pattern.end()), predicate);

        if (match_result.begin() == data.end())
        {
            break;
        }

        std::size_t offset = std::distance(data.begin(), match_result.begin());
        results.push_back(offset);

        it = match_result.begin() + 1;
        if (it == data.end())
        {
            break;
        }
    }

    return results;
}

void patch_checksum_checks(std::vector<std::uint8_t>& data)
{
    const auto pattern = std::vector<std::optional<std::uint8_t>>{ 0x03, 0x06, 0x46, 0x49, 0x75, 0xFA };

    // find "sub [esp+10h+var_10], eax"
    const auto predicate = [](const ZydisInstruction& instr)
    {
        return instr.backing.info.mnemonic == ZYDIS_MNEMONIC_SUB &&
            instr.backing.info.operand_count >= 2 &&
            instr.backing.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            instr.backing.operands[0].mem.base == ZYDIS_REGISTER_ESP &&
            instr.backing.operands[1].reg.value == ZYDIS_REGISTER_EAX;
    };

    for (const auto& offset : find_patterns(data, pattern))
    {
        std::print("Checksum loop found at: 0x{:x}\n", g_image_base + offset);

        auto instr = disassemble_until(data, offset, g_image_base + offset, predicate);
        if (!instr)
        {
            std::print(std::cerr, "Could not find tamper instruction\n");
            continue;
        }

        std::print("Found tamper instruction at: 0x{:x}\n", g_image_base + instr->offset);

        // replace with NOPs
        std::memset(&data[instr->offset], 0x90, 3);
    }
}

void patch_deco_checks(std::vector<std::uint8_t>& data)
{
    constexpr auto PROGRESSIVE_DECOMPRESS_OFFSET = 20;

    const auto pattern = std::vector<std::optional<std::uint8_t>>{
        0xBA, {}, 0x00, 0x00, 0x00,   // mov edx, trackNumber
        0x52,                         // push edx
        0x33, 0xC0,                   // xor eax, eax
        0xA0, {}, {}, {}, {},         // mov al, driveLetter
        0x50,                         // push eax
    };

    const auto cmp_predicate = [](const ZydisInstruction& instr) -> bool
    {
        // check if instruction is a CMP with immediate value and memory operand using EBP
        return instr.backing.info.mnemonic == ZYDIS_MNEMONIC_CMP &&
            instr.backing.info.operand_count >= 2 &&
            instr.backing.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            instr.backing.operands[0].mem.base == ZYDIS_REGISTER_EBP &&
            instr.backing.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
    };

    for (const auto& image_offset : find_patterns(data, pattern))
    {
        const std::size_t virtual_address = g_image_base + image_offset;
        const std::size_t drm_address = virtual_address + PROGRESSIVE_DECOMPRESS_OFFSET;

        std::print("Prologue to ProgressiveDecompress_24 found at: 0x{:x}\n", virtual_address);
        std::print("Setup for ProgressiveDecompress_24 at: 0x{:x}\n", drm_address);

        auto cmp_instr = disassemble_until(data, image_offset, virtual_address, cmp_predicate);
        if (!cmp_instr)
        {
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
        // .text:1002B4E7 BA 76 49 07 10  mov     edx, offset ProgressiveDecompress_24
        // .text:1002B4EC 52              push    edx
        // .text:1002B4ED C3              retn

        // into the following sequence

        // 023DB4E6 | 83C4 08                  | add esp,8                   
        // 023DB4E9 | B8 2E0A4B00              | mov eax,MAGIC              

        // 83 C4 08 = add esp, 8
        data[patch_offset] = 0x83;
        data[patch_offset + 1] = 0xC4;
        data[patch_offset + 2] = 0x08;

        // B8 xx xx xx xx = MOV EAX, imm32
        data[patch_offset + 3] = 0xB8;
        data[patch_offset + 4] = static_cast<std::uint8_t>(magic_value & 0xFF);
        data[patch_offset + 5] = static_cast<std::uint8_t>((magic_value >> 8) & 0xFF);
        data[patch_offset + 6] = static_cast<std::uint8_t>((magic_value >> 16) & 0xFF);
        data[patch_offset + 7] = static_cast<std::uint8_t>((magic_value >> 24) & 0xFF);

        std::print("Patched ProgressiveDecompress_24 setup:\n");
        disassemble_until(data, image_offset, virtual_address, cmp_predicate);

        // remove the relocation entry for the ProgressiveDecompress_24 call
        std::print("\n*** Removing relocation entries for ProgressiveDecompress_24 ***\n");
        remove_relocation_entry(data, patch_offset + 1); // Address bytes start at offset+1
        std::print("\n");
    }
}

void patch_initial_cd_checks(std::vector<std::uint8_t>& data)
{
    const auto iat_lut = build_iat_lookup_table(data);

    int offset = 0;
    while (offset < static_cast<int>(data.size()))
    {
        // we're just bruteforcing through the file, expect errors
        auto instr = ZydisInstruction::disassemble(data, offset, g_image_base + offset);
        if (!instr)
        {
            offset++;
            continue;
        }

        // skip if not call instruction
        if (instr->backing.info.mnemonic != ZYDIS_MNEMONIC_CALL ||
            instr->backing.operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY)
        {
            offset++;
            continue;
        }

        // check if this is a call to a CD-check function
        const auto iat_address = instr->backing.operands[0].mem.disp.value;
        if (!iat_lut.contains(iat_address))
        {
            offset++;
            continue;
        }

        std::print("Found call to {} at 0x{:x}\n", iat_lut.at(iat_address), g_image_base + offset);

        // find next JCC
        const auto jcc_predicate = [](const ZydisInstruction& instr)
        {
            return instr.backing.info.mnemonic == ZYDIS_MNEMONIC_JZ ||
                instr.backing.info.mnemonic == ZYDIS_MNEMONIC_JBE;
        };

        auto jcc_instr = disassemble_until(data, offset, g_image_base + offset, jcc_predicate);
        if (!jcc_instr)
        {
            offset++;
            continue;
        }

        std::print("Found JCC at 0x{:x}\n", g_image_base + jcc_instr->offset);

        // invert JCC
        switch (jcc_instr->backing.info.mnemonic)
        {
        case ZYDIS_MNEMONIC_JZ:
            if (data[jcc_instr->offset] == 0x74)
            {
                data[jcc_instr->offset] = 0x75; // JNZ short
            }
            else if (data[jcc_instr->offset] == 0x0F && data[jcc_instr->offset + 1] == 0x84)
            {
                data[jcc_instr->offset + 1] = 0x85; // JNZ far
            }
            break;
        case ZYDIS_MNEMONIC_JBE:
            if (data[jcc_instr->offset] == 0x76)
            {
                data[jcc_instr->offset] = 0x77; // JNBE short
            }
            else if (data[jcc_instr->offset] == 0x0F && data[jcc_instr->offset + 1] == 0x86)
            {
                data[jcc_instr->offset + 1] = 0x87; // JNBE far
            }
            break;
        default:
            std::print(std::cerr, "Unknown JCC at 0x{:x}\n", g_image_base + jcc_instr->offset);
            return;
        }

        // dump to confirm patch
        disassemble_until(data, offset, g_image_base + offset, [](const ZydisInstruction& instr)
        {
            return instr.backing.info.mnemonic == ZYDIS_MNEMONIC_JNZ ||
                instr.backing.info.mnemonic == ZYDIS_MNEMONIC_JNBE;
        });

        return;
    }

    std::print(std::cerr, "Could not find CD TOC check to patch\n");
}

int main(int argc, char* argv[])
{
    const fs::path binary_path = argv[1];
    std::print("Executable: {}\n", binary_path.string());

    auto buffer = read_file(binary_path);
    std::print("Size: {} bytes\n", buffer.size());

    auto parser = ParsePEFromBuffer(makeBufferFromPointer(buffer.data(), buffer.size()));
    g_image_base = parser->peHeader.nt.OptionalHeader.ImageBase;
    DestructParsedPE(parser);
    std::print("Image base: 0x{:x}\n", g_image_base);

    std::print("\n*** Patching initial CD checks ***\n");
    patch_initial_cd_checks(buffer);

    std::print("\n*** Patching checksum checks ***\n");
    patch_checksum_checks(buffer);

    std::print("\n*** Patching ProgressiveDecompress_24 CD TOC checks ***\n");
    patch_deco_checks(buffer);

    fs::path backup_path = binary_path;
    fs::path extension = backup_path.extension();
    backup_path.replace_filename(binary_path.stem().string() + ".nocd" + extension.string());
    std::print("Writing crack to: {}\n", backup_path.string());
    write_file(backup_path, buffer);

    return 0;
}
