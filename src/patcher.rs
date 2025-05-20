use crate::pattern;
use goblin::{Object, pe::PE};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::collections::HashMap;

pub struct Patcher {
    buffer: Vec<u8>,
}

impl Patcher {
    pub fn new(buffer: Vec<u8>) -> Self {
        Self { buffer }
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub fn get_base_address(&self) -> usize {
        self.with_pe_image(|pe| {
            pe.header.optional_header.unwrap().windows_fields.image_base as usize
        })
    }

    pub fn patch_checksum_checks(&mut self) {
        stdlog!("\n*** Patching checksum checks ***");

        let pattern = pattern!({0x03, 0x06, 0x46, 0x49, 0x75, 0xFA});
        let results = pattern::find_all(&self.buffer, pattern);
        if results.is_empty() {
            stdlog!("No checksum checks found\n");
            return;
        }

        for idx in results {
            stdlog!(
                "Found checksum check at 0x{:04X}",
                self.get_base_address() + idx
            );
            // find "sub [esp+10h+var_10], eax"
            let instr = Self::disassemble_until(
                &self.buffer[idx..],
                self.get_base_address() + idx,
                |instruction| {
                    instruction.mnemonic() == Mnemonic::Sub
                        && instruction.op_count() == 2
                        && instruction.op0_kind() == OpKind::Memory
                        && instruction.op1_register() == Register::EAX
                },
                false,
            )
            .unwrap_or_else(|| panic!("Failed to find checksum fail instruction at 0x{:04X}", idx));
            stdlog!(
                "Patching checksum fail instruction at 0x{:04X}:",
                instr.ip()
            );

            // NOP out the instruction
            let physical_offset = instr.ip() as usize - self.get_base_address();
            self.buffer[physical_offset..physical_offset + 3].copy_from_slice(&[0x90; 3]);

            // print for comparison
            Self::disassemble_until(
                &self.buffer[idx..],
                self.get_base_address() + idx,
                |instruction| instruction.mnemonic() == Mnemonic::Nop,
                false,
            );

            stdlog!("");
        }
    }

    pub fn patch_early_cd_checks(&mut self) {
        stdlog!("*** Patching early CD checks ***");

        // we need to find the calls used to check for CD drives
        // we found that if the function fails, the early checks are simply skipped
        // without any side effects
        const GET_LOGICAL_DRIVES_LUT: [&str; 2] = ["GetLogicalDrives", "GetLogicalDriveStringsA"];
        let drm_imports = self.with_pe_image(|pe| {
            let mut used_imports = HashMap::new();
            for import in &pe.imports {
                if GET_LOGICAL_DRIVES_LUT.contains(&import.name.as_ref()) {
                    used_imports.insert(import.offset, String::from(import.name.clone()));
                    stdlog!(
                        "Found early CD check function in IAT: {} @ 0x{:04X}",
                        import.name,
                        self.get_base_address() + import.offset
                    );
                }
            }
            used_imports
        });

        if drm_imports.is_empty() {
            stdlog!("No early CD checks found");
            return;
        }

        // find the call instruction that calls the function
        // TODO: we only look for the first hit, what happens if there are multiple?
        // never had that case, but we should be careful
        let call_instr = Self::disassemble_until(
            &self.buffer,
            self.get_base_address(),
            |instruction| {
                instruction.mnemonic() == Mnemonic::Call
                    && instruction.op0_kind() == OpKind::Memory
                    && drm_imports.contains_key(
                        &(instruction.ip_rel_memory_address() as usize)
                            .wrapping_sub(self.get_base_address()),
                    )
            },
            true,
        )
        .unwrap_or_else(|| panic!("Failed to find call instruction for early CD check"));
        stdlog!(
            "Found call instruction for early CD check at 0x{:04X}",
            call_instr.ip()
        );

        // find the next JCC and invert it
        // we may need to find other types of JCC instructions as well
        // i've only encountered JBE and JE so far tho
        let jcc_instr = Self::disassemble_until(
            &self.buffer[call_instr.ip() as usize - self.get_base_address()..],
            call_instr.ip() as usize,
            |instruction| {
                instruction.mnemonic() == Mnemonic::Jbe || instruction.mnemonic() == Mnemonic::Je
            },
            false,
        )
        .unwrap_or_else(|| {
            panic!(
                "Failed to find JCC instruction after call instruction at 0x{:04X}",
                call_instr.ip()
            )
        });
        stdlog!("Found JCC instruction at 0x{:04X}", jcc_instr.ip());

        // invert the JCC instruction
        let physical_offset = jcc_instr.ip() as usize - self.get_base_address();
        match jcc_instr.mnemonic() {
            Mnemonic::Je if self.buffer[physical_offset] == 0x74 => {
                self.buffer[physical_offset] = 0x75 // JNE near
            }
            Mnemonic::Je if self.buffer[physical_offset] == 0x0F => {
                self.buffer[physical_offset + 1] = 0x85 // JNE far
            }
            Mnemonic::Jbe if self.buffer[physical_offset] == 0x76 => {
                self.buffer[physical_offset] = 0x77 // JNBE near
            }
            Mnemonic::Jbe if self.buffer[physical_offset] == 0x0F => {
                self.buffer[physical_offset + 1] = 0x87 // JNBE far
            }
            _ => panic!("Unsupported JCC instruction"),
        };

        stdlog!(
            "\nPatched JCC instruction at 0x{:04X}:",
            jcc_instr.ip() as usize
        );

        // disassemble to see if it worked
        Self::disassemble_until(
            &self.buffer[call_instr.ip() as usize - self.get_base_address()..],
            call_instr.ip() as usize,
            |instruction| instruction.ip() == jcc_instr.ip(),
            false,
        );
    }

    pub fn patch_deco_checks(&mut self) {
        stdlog!("\n*** Patching ProgressiveDecompress_24 CD TOC checks ***");

        let pattern = pattern!({
            0xBA, {}, 0x00, 0x00, 0x00,    // mov edx, trackNumber
            0x52,                          // push edx
            0x33, 0xC0,                    // xor eax, eax
            0xA0, {}, {}, {}, {},          // mov al, driveLetter
            0x50,                          // push eax
        });

        // find the ProgressiveDecompress_24 call prologue
        for idx in pattern::find_all(&self.buffer, pattern) {
            stdlog!(
                "Found pattern for ProgressiveDecompress_24 at 0x{:04X}:",
                self.get_base_address() + idx
            );

            // decode until we find the cmp instruction that verifies the TOC magic value
            let instr = Self::disassemble_until(
                &self.buffer[idx..],
                self.get_base_address() + idx,
                |instruction| {
                    instruction.mnemonic() == Mnemonic::Cmp
                        && instruction.op_count() >= 2
                        && instruction.op0_kind() == OpKind::Memory
                        && instruction.op1_kind() == OpKind::Immediate32
                },
                false,
            )
            .unwrap_or_else(|| {
                panic!(
                    "Failed to find cmp instruction for ProgressiveDecompress_24 at 0x{:04X}",
                    self.get_base_address() + idx
                )
            });
            stdlog!(
                "Prologue to ProgressiveDecompress_24 found at 0x{:04X}",
                instr.ip()
            );

            // we found the TOC magic value
            let magic_value = instr.immediate(1) as u32;
            stdlog!("TOC magic value found: 0x{:04X}", magic_value);

            // set the physical offset to the push just before ProgressiveDecompress_24 gets mov'd
            const PROGRESSIVE_DECOMPRESS_OFFSET: usize = 20;
            let physical_offset = idx + PROGRESSIVE_DECOMPRESS_OFFSET - 1;

            // ProgressiveDecompress_24 cleans up the stack ("retn 8")
            // so we need to incorporate that into our patch
            // we'll do this by overwriting the following sequence

            // .text:1002B4E6 52              push    edx
            // .text:1002B4E7 BA 76 49 07 10  mov     edx, offset
            // .text:1002B4EC 52              push    edx
            // .text:1002B4ED C3              retn

            // into the following sequence

            // 023DB4E6 | 83C4 08                  | add esp,8
            // 023DB4E9 | B8 2E0A4B00              | mov eax,MAGIC

            // this also gets rid of the push; ret indirection which is fine

            // 83 C4 08 = ADD ESP, 8
            self.buffer[physical_offset + 0] = 0x83;
            self.buffer[physical_offset + 1] = 0xC4;
            self.buffer[physical_offset + 2] = 0x08;

            // B8 xx xx xx xx = MOV EAX, imm32
            self.buffer[physical_offset + 3] = 0xB8;
            self.buffer[physical_offset + 4] = ((magic_value >> 0) & 0xFF) as u8;
            self.buffer[physical_offset + 5] = ((magic_value >> 8) & 0xFF) as u8;
            self.buffer[physical_offset + 6] = ((magic_value >> 16) & 0xFF) as u8;
            self.buffer[physical_offset + 7] = ((magic_value >> 24) & 0xFF) as u8;

            stdlog!("\nPatched ProgressiveDecompress_24 call:");
            Self::disassemble_until(
                &self.buffer[physical_offset..],
                self.get_base_address() + physical_offset,
                |instruction| {
                    instruction.mnemonic() == Mnemonic::Cmp
                        && instruction.op_count() >= 2
                        && instruction.op0_kind() == OpKind::Memory
                        && instruction.op1_kind() == OpKind::Immediate32
                },
                false,
            );

            stdlog!("\nRemoving relocation entry at 0x{:04X}", physical_offset);
            self.remove_relocation_entry(physical_offset + 1);
        }
    }

    fn disassemble_until<F>(
        buffer: &[u8],
        start_address: usize,
        predicate: F,
        quiet: bool,
    ) -> Option<Instruction>
    where
        F: Fn(&Instruction) -> bool,
    {
        let mut decoder = Decoder::with_ip(32, buffer, start_address as u64, DecoderOptions::NONE);

        while decoder.can_decode() {
            let instruction = decoder.decode();
            if !quiet {
                stdlog!("0x{:04X}: {}", instruction.ip(), instruction);
            }

            if predicate(&instruction) {
                return Some(instruction);
            }
        }

        None
    }

    fn remove_relocation_entry(&mut self, offset_to_remove: usize) {
        let (reloc_offset, reloc_size) = self.with_pe_image(|pe| {
            pe.sections
                .iter()
                .find(|sec| &sec.name[..6] == b".reloc")
                .map(|sec| {
                    (
                        sec.pointer_to_raw_data as usize,
                        sec.size_of_raw_data as usize,
                    )
                })
                .unwrap_or((0, 0))
        });

        if reloc_offset == 0 || reloc_size == 0 {
            stdlog!("No relocation section found");
            return;
        }

        // find section containing target offset & convert to RVA
        let target_rva = self
            .with_pe_image(|pe| {
                pe.sections
                    .iter()
                    .find(|sec| {
                        let start = sec.pointer_to_raw_data as usize;
                        let end = start + sec.size_of_raw_data as usize;
                        offset_to_remove >= start && offset_to_remove < end
                    })
                    .map(|sec| {
                        let section_offset = offset_to_remove - sec.pointer_to_raw_data as usize;
                        sec.virtual_address as usize + section_offset
                    })
            })
            .expect("Failed to find target section");

        let mut pos = reloc_offset;
        while pos + 8 <= reloc_offset + reloc_size {
            // read page RVA and block size
            let page_rva =
                u32::from_le_bytes(self.buffer[pos..pos + 4].try_into().unwrap()) as usize;
            let block_size =
                u32::from_le_bytes(self.buffer[pos + 4..pos + 8].try_into().unwrap()) as usize;

            if block_size == 0 || block_size > reloc_size {
                break;
            }

            if target_rva >= page_rva && target_rva < page_rva + 0x1000 {
                stdlog!(
                    "Found potential relocation block at offset 0x{:x}, page RVA: 0x{:x}, size: {}",
                    pos,
                    page_rva,
                    block_size
                );

                // process entries in this block
                for entry_pos in (pos + 8..pos + block_size).step_by(2) {
                    if entry_pos + 2 > self.buffer.len() {
                        break;
                    }

                    let entry = u16::from_le_bytes(
                        self.buffer[entry_pos..entry_pos + 2].try_into().unwrap(),
                    ) as usize;
                    let offset = entry & 0xFFF;
                    let entry_rva = page_rva + offset;

                    // check if entry matches target
                    if entry_rva == target_rva
                        || entry_rva == target_rva + 1
                        || entry_rva == target_rva + 2
                        || entry_rva == target_rva + 3
                    {
                        stdlog!(
                            "Found relocation entry at offset 0x{:x}, RVA: 0x{:x}",
                            entry_pos,
                            entry_rva
                        );

                        // zero the entry
                        self.buffer[entry_pos] = 0;
                        self.buffer[entry_pos + 1] = 0;

                        stdlog!("Removed relocation entry");
                    }
                }
            }

            pos += block_size;
        }
    }

    fn get_pe_image(&self) -> PE<'_> {
        match Object::parse(&self.buffer) {
            Ok(Object::PE(pe)) => pe,
            _ => panic!("Corrupted PE buffer"),
        }
    }

    fn with_pe_image<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&PE<'_>) -> R,
    {
        let pe = self.get_pe_image();
        f(&pe)
    }
}
