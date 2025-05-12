use std::collections::HashMap;

use crate::pattern;
use goblin::{Object, pe::PE};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

pub struct Patcher {
    buffer: Vec<u8>,
    base_address: usize,
    drm_import_lut: HashMap<String, usize>,
}

impl Patcher {
    pub fn new(buffer: Vec<u8>) -> Self {
        let image = match Object::parse(&buffer) {
            Ok(Object::PE(pe)) => pe,
            _ => panic!("Unsupported file format"),
        };

        let base_address = Self::get_base_address(&image);
        println!("Base address: 0x{:04X}", base_address);

        let drm_import_lut = Self::create_drm_import_lut(&image);
        for (name, rva) in &drm_import_lut {
            println!(
                "Found early CD drive check in IAT: {} @ 0x{:04X}",
                name,
                base_address + rva
            );
        }

        Self {
            buffer,
            base_address,
            drm_import_lut,
        }
    }

    fn get_pe_image(&self) -> PE<'_> {
        match Object::parse(&self.buffer) {
            Ok(Object::PE(pe)) => pe,
            _ => panic!("Corrupted PE buffer"),
        }
    }

    pub fn with_pe_image<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&PE<'_>) -> R,
    {
        let pe = self.get_pe_image();
        f(&pe)
    }

    pub fn patch_checksum_checks(&mut self) {
        println!("\n*** Patching checksum checks ***");

        let pattern = pattern!({0x03, 0x06, 0x46, 0x49, 0x75, 0xFA});
        let results = pattern::find_all(&self.buffer, pattern);
        if results.is_empty() {
            println!("No checksum checks found");
            return;
        }

        for idx in results {
            println!("Found checksum check at 0x{:04X}", self.base_address + idx);
            // find "sub [esp+10h+var_10], eax"
            let instr = Self::disassemble_until(
                &self.buffer[idx..],
                self.base_address + idx,
                |instruction| {
                    instruction.mnemonic() == Mnemonic::Sub
                        && instruction.op_count() == 2
                        && instruction.op0_kind() == OpKind::Memory
                        && instruction.op1_register() == Register::EAX
                },
            );
            println!("Found checksum fail instruction at 0x{:04X}", instr.ip());

            // NOP out the instruction
            let physical_offset = instr.ip() as usize - self.base_address;
            self.buffer[physical_offset..physical_offset + 3].copy_from_slice(&[0x90; 3]);
        }
    }

    pub fn patch_deco_checks(&mut self) {
        println!("\n*** Patching ProgressiveDecompress_24 CD TOC checks ***");
        let pattern = pattern!({
            0xBA, {}, 0x00, 0x00, 0x00,    // mov edx, trackNumber
            0x52,                          // push edx
            0x33, 0xC0,                    // xor eax, eax
            0xA0, {}, {}, {}, {},          // mov al, driveLetter
            0x50,                          // push eax
        });

        // find the ProgressiveDecompress_24 call prologue
        for idx in pattern::find_all(&self.buffer, pattern) {
            println!(
                "Found pattern for ProgressiveDecompress_24 at 0x{:04X}:",
                self.base_address + idx
            );

            // decode until we find the cmp instruction that verifies the TOC magic value
            let instr = Self::disassemble_until(
                &self.buffer[idx..],
                self.base_address + idx,
                |instruction| {
                    instruction.mnemonic() == Mnemonic::Cmp
                        && instruction.op_count() >= 2
                        && instruction.op0_kind() == OpKind::Memory
                        && instruction.op1_kind() == OpKind::Immediate32
                },
            );
            println!(
                "Prologue to ProgressiveDecompress_24 found at 0x{:04X}",
                instr.ip()
            );

            // we found the TOC magic value
            let magic_value = instr.immediate(1) as u32;
            println!("TOC magic value found: 0x{:04X}", magic_value);

            // set the physical offset to the push just before ProgressiveDecompress_24 gets mov'd
            const PROGRESSIVE_DECOMPRESS_OFFSET: usize = 20;
            let physical_offset = idx + PROGRESSIVE_DECOMPRESS_OFFSET - 1;

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
            self.buffer[physical_offset + 0] = 0x83;
            self.buffer[physical_offset + 1] = 0xC4;
            self.buffer[physical_offset + 2] = 0x08;

            // B8 xx xx xx xx = MOV EAX, imm32
            self.buffer[physical_offset + 3] = 0xB8;
            self.buffer[physical_offset + 4] = ((magic_value >> 0) & 0xFF) as u8;
            self.buffer[physical_offset + 5] = ((magic_value >> 8) & 0xFF) as u8;
            self.buffer[physical_offset + 6] = ((magic_value >> 16) & 0xFF) as u8;
            self.buffer[physical_offset + 7] = ((magic_value >> 24) & 0xFF) as u8;

            println!("\nPatched ProgressiveDecompress_24 call:");
            Self::disassemble_until(
                &self.buffer[physical_offset..],
                self.base_address + physical_offset,
                |instruction| {
                    instruction.mnemonic() == Mnemonic::Cmp
                        && instruction.op_count() >= 2
                        && instruction.op0_kind() == OpKind::Memory
                        && instruction.op1_kind() == OpKind::Immediate32
                },
            );

            println!("\nRemoving relocation entry at 0x{:04X}", physical_offset);
            self.remove_relocation_entry(physical_offset + 1);
        }
    }

    fn disassemble_until(
        buffer: &[u8],
        start_address: usize,
        predicate: fn(&Instruction) -> bool,
    ) -> Instruction {
        let mut decoder = Decoder::with_ip(32, buffer, start_address as u64, DecoderOptions::NONE);

        while decoder.can_decode() {
            let instruction = decoder.decode();
            println!("0x{:04X}: {}", instruction.ip(), instruction);

            if predicate(&instruction) {
                return instruction;
            }
        }

        panic!("Failed to find instruction matching predicate");
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
                .expect("Failed to find .reloc section")
        });

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
                println!(
                    "Found potential relocation block at offset 0x{:x}, page RVA: 0x{:x}, size: {}",
                    pos, page_rva, block_size
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
                        println!(
                            "Found relocation entry at offset 0x{:x}, RVA: 0x{:x}",
                            entry_pos, entry_rva
                        );

                        // zero the entry
                        self.buffer[entry_pos] = 0;
                        self.buffer[entry_pos + 1] = 0;

                        println!("Removed relocation entry");
                    }
                }
            }

            pos += block_size;
        }
    }

    fn create_drm_import_lut(image: &PE<'_>) -> HashMap<String, usize> {
        let mut drm_import_lut = HashMap::new();

        for import in &image.imports {
            if Self::is_early_cd_drive_check(&import.name) {
                drm_import_lut.insert(String::from(import.name.clone()), import.rva);
            }
        }

        drm_import_lut
    }

    fn get_base_address(image: &PE<'_>) -> usize {
        image
            .header
            .optional_header
            .unwrap()
            .windows_fields
            .image_base as usize
    }

    fn is_early_cd_drive_check(name: &str) -> bool {
        name == "GetLogicalDrives" || name == "GetLogicalDriveStringsA"
    }
}
