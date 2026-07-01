# Hollow

**hollow** is a shellcode loader generator. You give it a raw shellcode binary and a profile, and it spits out a compiled Windows PE loader with your shellcode encrypted inside.

## Getting Started

Binaries are available on the [releases](https://github.com/kanyo/hollow/releases) page, or build from source:

```
go build -o hollow .
```

Requires `x86_64-w64-mingw32-gcc` for cross-compilation.

On Arch Linux: `pacman -S mingw-w64-gcc`
On Debian/Ubuntu: `apt install gcc-mingw-w64-x86-64`

## Usage

```
./hollow -shellcode payload.bin -profile profiles/new_process_injection_sc.json
```

| Flag | Description |
|------|-------------|
| `-shellcode` | Path to raw shellcode (.bin) |
| `-profile` | Path to a profile JSON file |
| `-templates` | Templates directory (default: `./templates`) |

## How does it work?

hollow follows a three-step pipeline: **encrypt**, **substitute**, **compile**.

Your shellcode is encrypted with AES-256-CBC using a randomly generated key and IV on every run. Both are embedded inside the output binary. The chosen C template then has its placeholders replaced with the encrypted shellcode, the key, and the IV, and the result is compiled into a stripped, statically linked PE by MinGW.

At runtime, the loader decrypts the shellcode using Windows BCrypt and executes it using whichever injection technique the template implements.

### Templates

Templates are the C source files that implement the actual injection logic. Each one lives in `templates/` and contains placeholder tokens (`${SHELLCODE}`, `${KEY}`, `${IV}`, `${TARGET_PROCESS}`) that hollow fills in before compilation. You select a template through your profile.

hollow ships with six templates:

| Template | Technique |
|----------|-----------|
| `new_process_injection` | Remote thread injection into a freshly spawned process |
| `new_process_injection_sc` | Same, via direct syscalls (Hell's Gate) |
| `remote_thread_injection` | Classic remote thread injection into an existing process |
| `remote_thread_injection_sc` | Same, via direct syscalls (Hell's Gate) |
| `earlybird_apc` | Early Bird APC injection |
| `dll_sideload` | DLL sideloading, produces a DLL instead of an EXE |

You can write your own templates and drop them in `templates/` — hollow will pick them up automatically as long as your profile points to them.

### Profiles

Profiles are JSON files that tell hollow which template to use, what process to target, and how to compile the output. They live in `profiles/` and are meant to be customized per engagement.

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

`output_type` is either `exe` or `dll`. Set `automatic: false` to dump the substituted C source to disk instead of compiling it, useful if you want to modify the code before building.

The output file is written to `output_dir`, named `{template}_loader.{exe|dll}`.

## Templates in detail

### New Process Injection

Template: `new_process_injection`

**Technique:** Remote Thread Injection into a freshly spawned process.

Spawns the target process with `CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW`, waits two seconds for it to initialize, then allocates memory in its address space, writes the decrypted shellcode, marks it executable, and creates a remote thread pointing at it. The BREAKAWAY flag is required when the loader is launched from WinRM, which wraps all processes in a job object. Target is a full executable path.

Win32 calls: `CreateProcessA`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread`.

---

### New Process Injection via Direct Syscalls

Template: `new_process_injection_sc`

**Technique:** Remote Thread Injection into a freshly spawned process, via direct syscalls (Hell's Gate).

Same behavior as `new_process_injection`, but every allocation and threading call bypasses the Win32 layer entirely. SSNs are resolved from ntdll at runtime and executed via the raw `syscall` instruction. See the benchmark section.

---

### Remote Thread Injection

Template: `remote_thread_injection`

**Technique:** Classic Remote Thread Injection into an existing process.

Finds a running process by name using `CreateToolhelp32Snapshot`, opens a handle to it, then allocates memory, writes the shellcode, and creates a remote thread. No new process is spawned. Best used against long-lived processes like `explorer.exe`. Target is a process image name, not a full path.

Win32 calls: `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread`.

---

### Remote Thread Injection via Direct Syscalls

Template: `remote_thread_injection_sc`

**Technique:** Classic Remote Thread Injection into an existing process, via direct syscalls (Hell's Gate).

Same behavior as `remote_thread_injection`, bypassing the Win32 layer. See the benchmark section.

---

### Early Bird APC Injection

Template: `earlybird_apc`

**Technique:** Early Bird APC Injection (CyberArk, 2018).

Spawns the target process in a suspended state (`CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW`), writes the decrypted shellcode into its address space, then queues an Asynchronous Procedure Call (APC) to the main thread pointing at the shellcode via `QueueUserAPC`, and resumes with `ResumeThread`. Because the APC fires before the process entry point runs, the shellcode executes before any defensive tooling in the process has initialized. Avoids the `VirtualAllocEx + WriteProcessMemory + CreateRemoteThread` triad entirely.

---

### DLL Sideload

Template: `dll_sideload`

**Technique:** DLL Sideloading / In-Process Shellcode Execution.

Produces a DLL instead of an EXE. On `DLL_PROCESS_ATTACH`, a thread is spawned that decrypts and executes the shellcode in-process: `VirtualAlloc`, `memcpy`, `VirtualProtect`, then a direct function call into the shellcode. The host process must remain alive while the payload initializes (around 10 seconds for a Sliver beacon). Deploy by dropping the DLL in a location where a legitimate binary will load it via a missing DLL search path entry.

---

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

## Contributing

Contributions are welcome. If you have a template you've written and want to add it, or improvements to existing ones, feel free to open a PR. If you find a bug or have a suggestion, open an issue.

The goal of this tool is to make the loader development process easier, not to be a finished product. New templates, better profiles, and improvements to the core are all fair game. hollow was also built with the intent of helping people understand the concepts behind shellcode loaders and injection techniques, so clear and readable template code is just as valuable as functionality.

## Blog

I will be detailing the concepts behind each technique and the full usage of hollow on my blog very soon. Stay tuned.

## References

- [ldrgen](https://github.com/gatariee/ldrgen) by gatari, inspiration and reference for shellcode loader design
