# Noviy Disk DRM Patcher
A tool that automates the process of disabling the CD and anti-piracy checks found in Noviy Disk's custom DRM solution. Windows, Linux and macOS supported - and browser version over [here](https://noviy.layle.dev).  
Technical details about the DRM can be found on [my blog post](https://layle.me/posts/lego-rock-raiders-ru/) where I talked about cracking it for Lego Rock Raiders.

## Building
[![Build](https://github.com/ioncodes/noviy_nocd/actions/workflows/build.yml/badge.svg)](https://github.com/ioncodes/noviy_nocd/actions/workflows/build.yml)  

```bash
git clone https://github.com/ioncodes/noviy_nocd
cd noviy_nocd
cargo build --release

# to build the wasm portion (optional; only for web)
cargo install wasm-pack
wasm-pack build --release -d web/wasm --target web
```

## Usage
```
noviy_nocd.exe <input> [output]
```

The exact input file that needs to be provided may vary depending on the title. There is a compatibility section down below that states which file needs to be passed to this tool for each *known* title. When in doubt, start by passing the main executable and if that doesn't work try some files with the `.DLL` extension. Technical note: You may also check which file imports `DECO_24.DLL`, that's the one.

Note: The patcher will automatically attempt to write the file at `/input/folder/filename.nocd.exe` or similar. This will fail if you do not have write access to the folder. Either run as administrator or specify a full output path incl. the filename that is writable.

<details>
    <summary>Example output</summary>
    
  ```
$ .\noviy_nocd.exe 'C:\Program Files (x86)\LEGO Racers 2\Lego Racers 2.exe'
Patching: C:\Program Files (x86)\LEGO Racers 2\Lego Racers 2.exe
Output: C:\Program Files (x86)\LEGO Racers 2\Lego Racers 2.nocd.exe
File size: 1339392 bytes
Image base: 0x400000

*** Patching checksum checks ***
Found checksum check at 0x410AB6
0x410AB6: add eax,[esi]
0x410AB8: inc esi
0x410AB9: dec ecx
0x410ABA: jne short 00410AB6h
0x410ABC: pop esi
0x410ABD: mov edx,410AD1h
0x410AC2: push edx
0x410AC3: sub eax,0BC13601Fh
0x410AC8: sub [esp],eax
Patching checksum fail instruction at 0x410AC8:
0x410AB6: add eax,[esi]
0x410AB8: inc esi
0x410AB9: dec ecx
0x410ABA: jne short 00410AB6h
0x410ABC: pop esi
0x410ABD: mov edx,410AD1h
0x410AC2: push edx
0x410AC3: sub eax,0BC13601Fh
0x410AC8: nop

Found checksum check at 0x410AED
0x410AED: add eax,[esi]
0x410AEF: inc esi
0x410AF0: dec ecx
0x410AF1: jne short 00410AEDh
0x410AF3: pop esi
0x410AF4: mov edx,410B0Bh
0x410AF9: push edx
0x410AFA: mov edx,410AD4h
0x410AFF: sub eax,[edx+4]
0x410B02: sub [esp],eax
Patching checksum fail instruction at 0x410B02:
0x410AED: add eax,[esi]
0x410AEF: inc esi
0x410AF0: dec ecx
0x410AF1: jne short 00410AEDh
0x410AF3: pop esi
0x410AF4: mov edx,410B0Bh
0x410AF9: push edx
0x410AFA: mov edx,410AD4h
0x410AFF: sub eax,[edx+4]
0x410B02: nop

*** Patching early CD checks ***
Found early CD check function in IAT: GetLogicalDriveStringsA @ 0x523180
Found call instruction for early CD check at 0x4BFAD3
0x4BFAD3: call dword ptr ds:[523180h]
0x4BFAD9: mov ebp,eax
0x4BFADB: shr ebp,2
0x4BFADE: je near ptr 004BFBBAh
Found JCC instruction at 0x4BFADE

Patched JCC instruction at 0x4BFADE:
0x4BFAD3: call dword ptr ds:[523180h]
0x4BFAD9: mov ebp,eax
0x4BFADB: shr ebp,2
0x4BFADE: jne near ptr 004BFBBAh

*** Patching ProgressiveDecompress_24 CD TOC checks ***
Found pattern for ProgressiveDecompress_24 at 0x4106F1:
0x4106F1: mov edx,2
0x4106F6: push edx
0x4106F7: xor eax,eax
0x4106F9: mov al,ds:[54F5A1h]
0x4106FE: push eax
0x4106FF: mov edx,41070Ch
0x410704: push edx
0x410705: mov edx,50DE40h
0x41070A: push edx
0x41070B: ret
0x41070C: mov [ebp-4],eax
0x41070F: cmp dword ptr [ebp-4],4E2514h
Prologue to ProgressiveDecompress_24 found at 0x41070F
TOC magic value found: 0x4E2514

Patched ProgressiveDecompress_24 call:
0x410704: add esp,8
0x410707: mov eax,4E2514h
0x41070C: mov [ebp-4],eax
0x41070F: cmp dword ptr [ebp-4],4E2514h

Removing relocation entry at 0x10704
No relocation section found

Writing: C:\Program Files (x86)\LEGO Racers 2\Lego Racers 2.nocd.exe
  ```

</details>

## Compatibility
| **Title**         | **Target**          | **CRC32**  | **Notes**                                                    |
| ----------------- | ------------------- | ---------- | ------------------------------------------------------------ |
| Lego Rock Raiders | `LegoRR.exe`        | `5435e147` | -                                                            |
| Lego Racers 2     | `Lego Racers 2.exe` | `d0288104` | -                                                            |
| Lego Alpha Team   | `LoadComp.dll`      | `31e3d676` | Requires a `Config.txt` file with `VerifyDiscVol  false` set |
| Lego Stunt Rally  | `_msr.exe`          | `ca2ce831` | Requires the game to be launched via `_msr.exe`              |

More titles may be compatible, these are the ones we've tested thus far. You can find out whether your software/game is protected by Noviy's DRM by checking the installation folder. Presence of a file called `DECO_24.DLL` suggests protection.

## Features
* Patches all occurences of checksum checks via byte pattern matching (NOPs the code patch)
* Patches the TOC (`ProgressiveDecompress_24` in `DECO_24.DLL`) callers/checks inline by disassembling the game and finding the correct magic value (simple CMP predicate)
  * Removes the `.reloc` entry if one is found to prevent our patch from being "overwritten" (important in case of DLLs)
* Patches the initial CD checks by abusing the fact that when `GetLogicalDrives` and `GetLogicalDriveStringsA` "fail" the initial checks are skipped (inverts the jump condition)
  * Uses instruction matching (simple JCC predicates)

## Attributions
* Installer creation and testing by various members of [The Research Realm](https://researchrealm.net/)
* Favicon drawn by my girlfriend
