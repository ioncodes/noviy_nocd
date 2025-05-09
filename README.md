# Noviy Disk DRM Patcher
A tool that automates the process of disabling the CD and anti-piracy checks found in Noviy Disk's custom DRM solution.

## Building
[![Build](https://github.com/ioncodes/noviy_nocd/actions/workflows/build.yml/badge.svg)](https://github.com/ioncodes/noviy_nocd/actions/workflows/build.yml)  
Note: A compiler with support for C++23 features (namely `std::format` and `std::print`) is required. Support has been tested using GCC 14 and MSVC.

```bash
git clone https://github.com/ioncodes/noviy_nocd
cd noviy_nocd
git submodule update --init --recursive
mkdir build
cd build
cmake .. # or "CXX=$(which g++-14) cmake .."
cmake --build . --config Release --target noviy_nocd -j 18
```

## Usage
```
layle@pwn:~$ ./noviy_nocd /tmp/LegoRR.exe
```
This will create the patched binary at `/tmp/LegoRR.nocd.exe`.

<details>
    <summary>Example output</summary>
    
  ```
layle@pwn:~$ ./noviy_nocd /tmp/LegoRR.exe
Executable: /tmp/LegoRR.exe
Size: 739328 bytes
Image base: 0x400000

*** Patching initial CD checks ***
Found GetLogicalDrives in IAT: 0x49f0d0
Found call to GetLogicalDrives at 0x47749f
000000000047749F  call [0x0049F0D0]
00000000004774A5  cmp eax, ebx
00000000004774A7  jz 0x004775A4
Found JCC at 0x4774a7
000000000047749F  call [0x0049F0D0]
00000000004774A5  cmp eax, ebx
00000000004774A7  jnz 0x004775A4

*** Patching checksum checks ***
Checksum loop found at: 0x437adf
0000000000437ADF  add eax, [esi]
0000000000437AE1  inc esi
0000000000437AE2  dec ecx
0000000000437AE3  jnz 0x00437ADF
0000000000437AE5  pop esi
0000000000437AE6  mov edx, 0x4386FA
0000000000437AEB  push edx
0000000000437AEC  sub eax, 0xBC13601F
0000000000437AF1  sub [esp], eax
Found tamper instruction at: 0x437af1
Checksum loop found at: 0x437b16
0000000000437B16  add eax, [esi]
0000000000437B18  inc esi
0000000000437B19  dec ecx
0000000000437B1A  jnz 0x00437B16
0000000000437B1C  pop esi
0000000000437B1D  mov edx, 0x438734
0000000000437B22  push edx
0000000000437B23  mov edx, 0x4386FD
0000000000437B28  sub eax, [edx+0x04]
0000000000437B2B  sub [esp], eax
Found tamper instruction at: 0x437b2b
Checksum loop found at: 0x4775fd
00000000004775FD  add eax, [esi]
00000000004775FF  inc esi
0000000000477600  dec ecx
0000000000477601  jnz 0x004775FD
0000000000477603  pop esi
0000000000477604  mov edx, 0x47821B
0000000000477609  push edx
000000000047760A  mov edx, 0x4781E4
000000000047760F  sub eax, [edx+0x04]
0000000000477612  sub [esp], eax
Found tamper instruction at: 0x477612
Checksum loop found at: 0x478cca
0000000000478CCA  add eax, [esi]
0000000000478CCC  inc esi
0000000000478CCD  dec ecx
0000000000478CCE  jnz 0x00478CCA
0000000000478CD0  pop esi
0000000000478CD1  mov edx, 0x4798E5
0000000000478CD6  push edx
0000000000478CD7  sub eax, 0xBC13601F
0000000000478CDC  sub [esp], eax
Found tamper instruction at: 0x478cdc
Checksum loop found at: 0x478d01
0000000000478D01  add eax, [esi]
0000000000478D03  inc esi
0000000000478D04  dec ecx
0000000000478D05  jnz 0x00478D01
0000000000478D07  pop esi
0000000000478D08  mov edx, 0x47991F
0000000000478D0D  push edx
0000000000478D0E  mov edx, 0x4798E8
0000000000478D13  sub eax, [edx+0x04]
0000000000478D16  sub [esp], eax
Found tamper instruction at: 0x478d16

*** Patching ProgressiveDecompress_24 CD TOC checks ***
Prologue to ProgressiveDecompress_24 found at: 0x437a7e
Setup for ProgressiveDecompress_24 at: 0x437a92
0000000000437A7E  mov edx, 0x02
0000000000437A83  push edx
0000000000437A84  xor eax, eax
0000000000437A86  mov al, [0x0076D164]
0000000000437A8B  push eax
0000000000437A8C  mov edx, 0x438699
0000000000437A91  push edx
0000000000437A92  mov edx, 0x472820
0000000000437A97  push edx
0000000000437A98  ret
0000000000437A99  mov [ebp-0x08], eax
0000000000437A9C  xor al, al
0000000000437A9E  mov [0x0076D164], al
0000000000437AA3  mov eax, [ebp+0x0C]
0000000000437AA6  test eax, eax
0000000000437AA8  jnz 0x00437AB7
0000000000437AAA  cmp dword ptr [ebp-0x08], 0x41321B
Magic value: 0x41321b
Patched ProgressiveDecompress_24 setup:
0000000000437A7E  mov edx, 0x02
0000000000437A83  push edx
0000000000437A84  xor eax, eax
0000000000437A86  mov al, [0x0076D164]
0000000000437A8B  push eax
0000000000437A8C  mov edx, 0x438699
0000000000437A91  add esp, 0x08
0000000000437A94  mov eax, 0x41321B
0000000000437A99  mov [ebp-0x08], eax
0000000000437A9C  xor al, al
0000000000437A9E  mov [0x0076D164], al
0000000000437AA3  mov eax, [ebp+0x0C]
0000000000437AA6  test eax, eax
0000000000437AA8  jnz 0x00437AB7
0000000000437AAA  cmp dword ptr [ebp-0x08], 0x41321B

*** Removing relocation entries for ProgressiveDecompress_24 ***
No relocation section found

Prologue to ProgressiveDecompress_24 found at: 0x478c6e
Setup for ProgressiveDecompress_24 at: 0x478c82
0000000000478C6E  mov edx, 0x03
0000000000478C73  push edx
0000000000478C74  xor eax, eax
0000000000478C76  mov al, [0x0076D164]
0000000000478C7B  push eax
0000000000478C7C  mov edx, 0x479889
0000000000478C81  push edx
0000000000478C82  mov edx, 0x472820
0000000000478C87  push edx
0000000000478C88  ret
0000000000478C89  mov [ebp-0x04], eax
0000000000478C8C  xor al, al
0000000000478C8E  mov [0x0076D164], al
0000000000478C93  cmp dword ptr [ebp-0x04], 0x43002F
Magic value: 0x43002f
Patched ProgressiveDecompress_24 setup:
0000000000478C6E  mov edx, 0x03
0000000000478C73  push edx
0000000000478C74  xor eax, eax
0000000000478C76  mov al, [0x0076D164]
0000000000478C7B  push eax
0000000000478C7C  mov edx, 0x479889
0000000000478C81  add esp, 0x08
0000000000478C84  mov eax, 0x43002F
0000000000478C89  mov [ebp-0x04], eax
0000000000478C8C  xor al, al
0000000000478C8E  mov [0x0076D164], al
0000000000478C93  cmp dword ptr [ebp-0x04], 0x43002F

*** Removing relocation entries for ProgressiveDecompress_24 ***
No relocation section found

Writing crack to: /tmp/LegoRR.nocd.exe
  ```

</details>

## Compatibility
| **Title**         | **Target**          | **CRC32**  | **Notes**                                                    |
| ----------------- | ------------------- | ---------- | ------------------------------------------------------------ |
| Lego Rock Raiders | `LegoRR.exe`        | `5435e147` | -                                                            |
| Lego Racers 2     | `Lego Racers 2.exe` | `d0288104` | -                                                            |
| Lego Alpha Team   | `LoadComp.dll`      | `31e3d676` | Requires a `Config.txt` file with `VerifyDiscVol  false` set |

More titles may be compatible, these are the ones we've tested thus far.

## Features
* Patches all occurences of checksum checks via byte pattern matching (NOPs the code patch)
* Patches the TOC (`ProgressiveDecompress_24` in `DECO_24.DLL`) callers/checks inline by disassembling the game and finding the correct magic value (simple CMP predicate)
  * Removes the `.reloc` entry if one is found to prevent our patch from being "overwritten" (important in case of DLLs)
* Patches the initial CD checks by abusing the fact that when `GetLogicalDrives` and `GetLogicalDriveStringsA` "fail" the initial checks are skipped (inverts the jump condition)
  * Uses instruction matching (simple JCC predicates)
