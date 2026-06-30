# Hollow

A shellcode loader generator for red team engagements. hollow takes raw shellcode, encrypts it with AES-256-CBC, and compiles it into a Windows PE loader or DLL using one of six injection templates. The output is a single self-contained binary with no runtime dependencies beyond the Windows API and BCrypt.

## How it works

hollow follows a three-step pipeline.

**Encrypt.** The input shellcode is padded to a 16-byte boundary (PKCS7) and encrypted with AES-256-CBC. A fresh 256-bit key and 128-bit IV are randomly generated for each build. Both are embedded inside the compiled loader.

**Substitute.** The selected C template contains placeholder tokens: `${SHELLCODE}`, `${KEY}`, `${IV}`, and `${TARGET_PROCESS}`. hollow replaces these with the encrypted byte arrays and the target executable path before the source ever touches the compiler.

**Compile.** The substituted C source is passed to `x86_64-w64-mingw32-gcc`, which produces a stripped, statically linked PE. Setting `automatic: false` in the profile skips compilation and writes the source to disk instead, so you can modify or compile it yourself.

At runtime, the loader decrypts the shellcode using Windows BCrypt (AES-256-CBC, in-place) and executes it via the chosen injection method. The key and IV are embedded in plaintext inside the binary, so this is not an evasion layer by itself. The actual evasion comes from the injection technique.

## Templates

### spawn

Spawns the target process with `CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW`, waits two seconds for it to initialize, then injects shellcode into its address space and starts a remote thread. The BREAKAWAY flag is required when the loader is launched from WinRM, which wraps all processes in a job object. Uses the Win32 injection triad: `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread`. Target is a full executable path.

### spawn_sc

Same behavior as spawn, but every allocation and threading call goes through the kernel directly via the `syscall` instruction rather than through Win32. See the benchmark section below.

### inject

Opens an existing process by name using `CreateToolhelp32Snapshot`, then injects shellcode via remote thread. No process is spawned. Best used against long-lived processes like `explorer.exe`. Target is a process image name, not a full path. Same Win32 injection triad as spawn.

### inject_sc

Same behavior as inject, direct syscall variant. See the benchmark section below.

### earlybird

Early-Bird APC injection. Spawns the target process suspended with `CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW`, queues an APC to the main thread pointing at the decrypted shellcode via `QueueUserAPC`, then resumes with `ResumeThread`. The shellcode executes before the process entry point runs. Avoids the `VirtualAllocEx + WriteProcessMemory + CreateRemoteThread` triad entirely.

### sideload

Produces a DLL instead of an EXE. On `DLL_PROCESS_ATTACH`, a thread is created that decrypts and executes the shellcode in-process using `VirtualAlloc`, `memcpy`, `VirtualProtect`, then a direct call. The host process must remain alive while the beacon initializes (around 10 seconds). Deploy by dropping the DLL somewhere a legitimate binary will load it.

## Benchmark: Win32 vs. direct syscalls

Tested on Windows 10 Build 19041, Windows Defender realtime protection enabled, definitions 1.453.354.0, with a 17 MB Donut-wrapped Sliver beacon as the payload:

| Template   | Defender behavioral alert            | Session established |
|------------|--------------------------------------|---------------------|
| spawn      | Trojan:Win64/AsyncRat.RPY!MTB        | yes                 |
| inject     | Trojan:Win64/AsyncRat.RPY!MTB        | yes                 |
| earlybird  | none                                 | yes                 |
| sideload   | none                                 | yes                 |
| spawn_sc   | none                                 | yes                 |
| inject_sc  | none                                 | yes                 |

`Trojan:Win64/AsyncRat.RPY!MTB` is a machine-threat-behavior rule triggered by the classic remote injection sequence: `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` called on a remote process handle through the Win32 API layer. Defender registers a kernel callback that fires when these three calls appear in sequence.

The spawn_sc and inject_sc templates bypass this by never calling those Win32 functions. Instead, they resolve the corresponding Windows kernel function numbers (syscall service numbers, or SSNs) directly from ntdll at runtime, then execute them via the raw `syscall` instruction. Defender's callback never fires because the monitored wrappers are never invoked.

SSN resolution uses Hell's Gate. Every ntdll stub that has not been patched by an EDR starts with the four-byte sequence `4C 8B D1 B8`. The two bytes at offset 4 are the SSN. hollow reads that value at runtime and stores it before the injection begins. The actual syscall is a GCC naked function containing nothing but `movq %rcx, %r10 / movl ssn(%rip), %eax / syscall / ret`, which is the exact instruction sequence the ntdll stub itself would execute.

On systems where ntdll stubs are patched by a full EDR (the prologue is replaced with a jump), the clean-stub check will fail and the loader will exit early rather than guess. Halo's Gate (scanning neighboring stubs to infer the SSN) is not implemented.

## Binary size

The loader code itself adds roughly 19 KB of overhead. The output binary size is essentially the size of the input shellcode. A 17 MB Sliver beacon produces an 18 MB loader. A typical Metasploit meterpreter shellcode (~200 KB) would produce a ~220 KB loader.

## Usage

### Build

```
go build -o hollow .
```

Requires `x86_64-w64-mingw32-gcc` in PATH for cross-compilation.

### Generate a loader

```
./hollow -shellcode payload.bin -profile profiles/spawn_sc.json
```

| Flag | Description |
|------|-------------|
| `-shellcode` | Path to raw shellcode (.bin) |
| `-profile` | Path to a profile JSON file |
| `-templates` | Templates directory (default: `./templates`) |

The output file is written to the `output_dir` specified in the profile, named `{template}_loader.{exe|dll}`.

### Profile format

```json
{
    "name": "Direct Syscall Spawn",
    "author": "",
    "template": "spawn_sc",
    "target_process": "C:\\Windows\\System32\\cmd.exe",
    "arch": "x64",
    "compile": {
        "automatic": true,
        "gcc": "x86_64-w64-mingw32-gcc",
        "strip": true,
        "output_type": "exe"
    },
    "output_dir": "./output"
}
```

`output_type` is either `exe` or `dll`. `strip: true` passes `-s` to GCC to remove the symbol table. Set `automatic: false` to write the substituted C source to `output_dir/loader.c` instead of compiling.

## Requirements

- Go 1.21+
- `x86_64-w64-mingw32-gcc` (MinGW-w64 cross-compiler)

On Arch Linux: `pacman -S mingw-w64-gcc`
On Debian/Ubuntu: `apt install gcc-mingw-w64-x86-64`
