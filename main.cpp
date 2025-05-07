#include <algorithm>
#include <cinttypes>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <optional>
#include <vector>
#include <array>

#include <Zydis/Zydis.h>
#include <pe-parse/parse.h>

namespace fs = std::filesystem;

static constexpr auto IMAGE_BASE = 0x00400000;

struct ZydisInstruction
{
    ZydisDisassembledInstruction backing;
    ZyanU64 runtime_address;
    ZyanUSize offset;

    [[nodiscard]] std::string to_string() const
    {
        char buffer[128];
        snprintf(buffer, sizeof(buffer), "%016" PRIX64 "  %s", runtime_address, backing.text);
        return std::string {buffer};
    }

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
        if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_COMPAT_32, runtime_address, &data[offset],
                                               data.size() - offset, &instruction)))
        {
            return ZydisInstruction {instruction, runtime_address, offset};
        }

        return std::nullopt;
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
        if (const auto instr = ZydisInstruction::disassemble(data, instr_offset, runtime_address + (instr_offset - start_offset)))
        {
            std::cout << instr->to_string() << std::endl;

            if (predicate(*instr))
            {
                return *instr;
            }
            instr_offset += instr->size();
            count++;
        }
        else
        {
            std::cerr << "Failed to disassemble instruction at offset: " << std::hex << instr_offset << std::endl;

            break;
        }
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

    using namespace peparse;
    const auto parser = ParsePEFromBuffer(makeBufferFromPointer(data.data(), data.size()));

    auto callback = [](void* context, const VA& addr, const std::string& module, const std::string& symbol) -> int {
        auto* table = static_cast<decltype(iat_lookup_table)*>(context);

        static constexpr std::array<const char*, 2> CD_CHECK_BYPASS = {
            "GetLogicalDriveStringsA", // Lego Racers 2
            "GetLogicalDrives"         // Lego Rock Raiders
        };

        if (std::ranges::find(CD_CHECK_BYPASS, symbol) != CD_CHECK_BYPASS.end())
        {
            std::cout << "Found " << symbol << " in IAT: 0x" << std::hex << addr << std::endl;
            (*table)[addr] = symbol;
        }

        return 0;
    };

    IterImpVAString(parser, callback, &iat_lookup_table);

    DestructParsedPE(parser);
    return iat_lookup_table;
}

std::vector<std::size_t> find_patterns(const std::vector<std::uint8_t>& data,
                                       const std::vector<std::optional<std::uint8_t>>& pattern)
{
    std::vector<std::size_t> results;

    auto predicate = [](const std::uint8_t& x, const std::optional<std::uint8_t>& y) {
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
    const auto pattern = std::vector<std::optional<std::uint8_t>> {0x03, 0x06, 0x46, 0x49, 0x75, 0xFA};

    // find "sub [esp+10h+var_10], eax"
    const auto predicate = [](const ZydisInstruction& instr) {
        return instr.backing.info.mnemonic == ZYDIS_MNEMONIC_SUB &&
               instr.backing.info.operand_count >= 2 &&
               instr.backing.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
               instr.backing.operands[0].mem.base == ZYDIS_REGISTER_ESP &&
               instr.backing.operands[1].reg.value == ZYDIS_REGISTER_EAX;
    };

    for (const auto& offset : find_patterns(data, pattern))
    {
        std::cout << "Checksum loop found at: 0x" << std::hex << IMAGE_BASE + offset << std::endl;

        const auto instr = disassemble_until(data, offset, IMAGE_BASE + offset, predicate);
        std::cout << "Found tamper instruction at: 0x" << std::hex << IMAGE_BASE + instr->offset << std::endl;

        for (int i = 0; i < 3; ++i)
        {
            data[instr->offset + i] = 0x90; // NOP
        }
    }
}

void patch_deco_checks(std::vector<std::uint8_t>& data)
{
    constexpr auto PROGRESSIVE_DECOMPRESS_OFFSET = 20;

    const auto pattern = std::vector<std::optional<std::uint8_t>> {
        0xBA, {},   0x00, 0x00, 0x00, // mov edx, trackNumber
        0x52,                         // push edx
        0x33, 0xC0,                   // xor eax, eax
        0xA0, {},   {},   {},   {},   // mov al, driveLetter
        0x50,                         // push eax
    };
    const auto cmp_predicate = [](const ZydisInstruction& instr) -> bool {
        // Check if instruction is a CMP with immediate value and memory operand using EBP
        return instr.backing.info.mnemonic == ZYDIS_MNEMONIC_CMP && instr.backing.info.operand_count >= 2 &&
               instr.backing.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
               instr.backing.operands[0].mem.base == ZYDIS_REGISTER_EBP &&
               instr.backing.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
    };

    for (const auto& image_offset : find_patterns(data, pattern))
    {
        const std::size_t virtual_address = IMAGE_BASE + image_offset;
        const std::size_t drm_address = virtual_address + PROGRESSIVE_DECOMPRESS_OFFSET;

        std::cout << "Prologue to ProgressiveDecompress_24 found at: 0x" << std::hex << virtual_address << std::endl;
        std::cout << "Setup for ProgressiveDecompress_24 at: 0x" << std::hex << drm_address << std::endl;

        if (auto cmp_instr = disassemble_until(data, image_offset, virtual_address, cmp_predicate))
        {
            auto magic_value = static_cast<std::uint32_t>(cmp_instr->backing.operands[1].imm.value.u);
            std::cout << "Magic value: 0x" << std::hex << magic_value << std::endl;

            // PRESUMED location of the "push edx, ProgressiveDecompress" -> we might have to rely on pattern scan
            // for this
            const std::size_t patch_offset = image_offset + PROGRESSIVE_DECOMPRESS_OFFSET;

            // B8 xx xx xx xx = MOV EAX, imm32
            data[patch_offset] = 0xB8;
            data[patch_offset + 1] = static_cast<std::uint8_t>(magic_value & 0xFF);
            data[patch_offset + 2] = static_cast<std::uint8_t>((magic_value >> 8) & 0xFF);
            data[patch_offset + 3] = static_cast<std::uint8_t>((magic_value >> 16) & 0xFF);
            data[patch_offset + 4] = static_cast<std::uint8_t>((magic_value >> 24) & 0xFF);
            data[patch_offset + 5] = 0x90; // NOP the "push edx"

            std::cout << "Patched ProgressiveDecompress_24 setup:" << std::endl;

            disassemble_until(data, image_offset, virtual_address, cmp_predicate);
        }
        else
        {
            std::cerr << "Couldn't find the magic CMP instruction" << std::endl;
        }
    }
}

void patch_initial_cd_checks(std::vector<std::uint8_t>& data)
{
    const auto iat_lut = build_iat_lookup_table(data);

    int offset = 0;
    while (true)
    {
        if (const auto instr = ZydisInstruction::disassemble(data, offset, IMAGE_BASE + offset))
        {
            if (instr->backing.info.mnemonic == ZYDIS_MNEMONIC_CALL &&
                instr->backing.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                const auto iat_address = instr->backing.operands[0].mem.disp.value;
                if (iat_lut.contains(iat_address))
                {
                    std::cout << "Found call to " << iat_lut.at(iat_address) << " at 0x" << std::hex
                              << IMAGE_BASE + offset << std::endl;

                    // Find next JZ
                    const auto predicate = [](const ZydisInstruction& instr) {
                        return instr.backing.info.mnemonic == ZYDIS_MNEMONIC_JZ;
                    };
                    
                    if (const auto instr = disassemble_until(data, offset, IMAGE_BASE + offset, predicate))
                    {
                        std::cout << "Found JZ at 0x" << std::hex << IMAGE_BASE + instr->offset << std::endl;

                        if (data[instr->offset] == 0x74)
                        {
                            data[instr->offset] = 0x75; // JNZ short
                        }
                        else if (data[instr->offset] == 0x0F && data[instr->offset + 1] == 0x84)
                        {
                            data[instr->offset + 1] = 0x85; // JNZ far
                        }
                        else
                        {
                            std::cerr << "Unknown JZ instruction at 0x" << std::hex << IMAGE_BASE + instr->offset << std::endl;
                        }

                        disassemble_until(data, offset, IMAGE_BASE + offset, [](const ZydisInstruction& instr) {
                            return instr.backing.info.mnemonic == ZYDIS_MNEMONIC_JNZ;
                        });
                    }

                    break;
                }
            }
        }

        offset++;
    }
}

int main(int argc, char* argv[])
{
    const fs::path binary_path = argv[1];
    std::cout << "Executable: " << binary_path << std::endl;

    auto buffer = read_file(binary_path);
    std::cout << "Size: " << buffer.size() << " bytes" << std::endl;

    patch_initial_cd_checks(buffer);
    patch_checksum_checks(buffer);
    patch_deco_checks(buffer);

    fs::path backup_path = binary_path;
    backup_path.replace_filename(binary_path.stem().string() + ".nocd.exe");
    std::cout << "Writing crack to: " << backup_path << std::endl;
    write_file(backup_path, buffer);

    return 0;
}
