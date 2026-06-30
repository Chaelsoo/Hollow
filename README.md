# hollow

A shellcode loader generator for red team engagements. hollow takes raw shellcode, encrypts it with AES-256-CBC, and compiles it into a Windows PE loader or DLL using one of six injection templates. The output is a single self-contained binary with no runtime dependencies beyond the Windows API and BCrypt.

## How it works

hollow follows a three-step pipeline.

**Encrypt.** The input shellcode is padded to a 16-byte boundary (PKCS7) and encrypted with AES-256-CBC. A fresh 256-bit key and 128-bit IV are randomly generated for each build. Both are embedded inside the compiled loader.

**Substitute.** The selected C template contains placeholder tokens: `${SHELLCODE}`, `${KEY}`, `${IV}`, and `${TARGET_PROCESS}`. hollow replaces these with the encrypted byte arrays and the target executable path before the source ever touches the compiler.

**Compile.** The substituted C source is passed to `x86_64-w64-mingw32-gcc`, which produces a stripped, statically linked PE. Setting `automatic: false` in the profile skips compilation and writes the source to disk instead, so you can modify or compile it yourself.

At runtime, the loader decrypts the shellcode using Windows BCrypt (AES-256-CBC, in-place) and executes it via the chosen injection method. The key and IV are embedded in plaintext inside the binary, so this is not an evasion layer by itself. The actual evasion comes from the injection technique.

## Templates

### new_process_injection

**Technique:** Remote Thread Injection into a freshly spawned process.

Spawns the target process with `CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW`, waits two seconds for it to initialize, then allocates memory in its address space, writes the decrypted shellcode, marks it executable, and creates a remote thread pointing at it. The BREAKAWAY flag is required when the loader is launched from WinRM, which wraps all processes in a job object. Target is a full executable path.

Win32 calls: `CreateProcessA`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread`.

### new_process_injection_sc

**Technique:** Remote Thread Injection into a freshly spawned process, via direct syscalls (Hell's Gate).

Same behavior as `new_process_injection`, but every allocation and threading call bypasses the Win32 layer entirely. SSNs are resolved from ntdll at runtime and executed via the raw `syscall` instruction. See the benchmark section.

### remote_thread_injection

**Technique:** Classic Remote Thread Injection into an existing process.

Finds a running process by name using `CreateToolhelp32Snapshot`, opens a handle to it, then allocates memory, writes the shellcode, and creates a remote thread. No new process is spawned. Best used against long-lived processes like `explorer.exe`. Target is a process image name, not a full path.

Win32 calls: `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread`.

### remote_thread_injection_sc

**Technique:** Classic Remote Thread Injection into an existing process, via direct syscalls (Hell's Gate).

Same behavior as `remote_thread_injection`, bypassing the Win32 layer. See the benchmark section.

### earlybird_apc

**Technique:** Early Bird APC Injection (CyberArk, 2018).

Spawns the target process in a suspended state (`CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW`), writes the decrypted shellcode into its address space, then queues an Asynchronous Procedure Call (APC) to the main thread pointing at the shellcode via `QueueUserAPC`, and resumes with `ResumeThread`. Because the APC fires before the process entry point runs, the shellcode executes before any defensive tooling in the process has initialized. Avoids the `VirtualAllocEx + WriteProcessMemory + CreateRemoteThread` triad entirely.

### dll_sideload

**Technique:** DLL Sideloading / In-Process Shellcode Execution.

Produces a DLL instead of an EXE. On `DLL_PROCESS_ATTACH`, a thread is spawned that decrypts and executes the shellcode in-process: `VirtualAlloc`, `memcpy`, `VirtualProtect`, then a direct function call into the shellcode. The host process must remain alive while the payload initializes (around 10 seconds for a Sliver beacon). Deploy by dropping the DLL in a location where a legitimate binary will load it via a missing DLL search path entry.

## Benchmark: Win32 vs. direct syscalls

Tested on Windows 10 Build 19041, Windows Defender realtime protection enabled, definitions 1.453.354.0, with a 17 MB Donut-wrapped Sliver beacon as the payload:

| Template                   | Defender behavioral alert     | Session established |
|----------------------------|-------------------------------|---------------------|
| new_process_injection      | Trojan:Win64/AsyncRat.RPY!MTB | yes                 |
| remote_thread_injection    | Trojan:Win64/AsyncRat.RPY!MTB | yes                 |
| earlybird_apc              | none                          | yes                 |
| dll_sideload               | none                          | yes                 |
| new_process_injection_sc   | none                          | yes                 |
| remote_thread_injection_sc | none                          | yes                 |

`Trojan:Win64/AsyncRat.RPY!MTB` is a machine-threat-behavior rule triggered by the classic remote injection sequence: `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` called on a remote process handle through the Win32 API layer. Defender registers a kernel callback that fires when these three calls appear in sequence.

The `_sc` templates bypass this by never calling those Win32 functions. Instead, they resolve the corresponding kernel syscall service numbers (SSNs) directly from ntdll at runtime using Hell's Gate: every unhooked ntdll stub starts with the four-byte prologue `4C 8B D1 B8`, and the SSN sits at offset 4. The actual syscall is a GCC naked function containing nothing but `movq %rcx, %r10 / movl ssn(%rip), %eax / syscall / ret`, which is the exact sequence the ntdll stub itself would execute. Defender's callback never fires because the monitored Win32 wrappers are never invoked.

On systems where ntdll stubs are patched by a full EDR (prologue replaced with a jump), the clean-stub check fails and the loader exits early. Halo's Gate (scanning neighboring stubs to infer the SSN) is not implemented.

## Binary size

The loader code adds roughly 19 KB of overhead. Output size is essentially the size of the input shellcode. A 17 MB Sliver beacon produces an 18 MB loader. A typical Metasploit shellcode (~200 KB) would produce a ~220 KB loader.

## Usage

### Build

```
go build -o hollow .
```

Requires `x86_64-w64-mingw32-gcc` in PATH for cross-compilation.

### Generate a loader

```
./hollow -shellcode payload.bin -profile profiles/new_process_injection_sc.json
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
    "name": "New Process Injection via Direct Syscalls",
    "author": "",
    "template": "new_process_injection_sc",
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
