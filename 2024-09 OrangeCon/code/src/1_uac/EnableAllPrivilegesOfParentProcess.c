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
 * Tool Help Library
 * 
 * WIN32 tool help functions, types, and definitions.
 * https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/
 */
#include <tlhelp32.h>

/**
 * Dynamically include Windows libraries.
 */
#pragma comment(lib, "ntdll.lib")

/**
 * NtQueryInformationProcess function definition.
 */
typedef LONG (NTAPI *PNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    UINT ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

/**
 * PROCESS_BASIC_INFORMATION struct definition.
 */
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

/**
 * Get the ID of the parent process (e.g. from cmd.exe when calling this executable in cmd.exe).
 * 
 * @param DWORD* dwParentProcessId The resulting process ID.
 * @return bool Positive if obtained succesfully.
 */
bool GetParentProcessId(DWORD* dwParentProcessId) {
    bool bResult = false;    
    ULONG qwReturnLength;
    PROCESS_BASIC_INFORMATION sProcessBasicInformation;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    if (!hProcess) {
        printf("[!] OpenProcess failed. Error: %u\n", GetLastError());
        goto CLEANUP_AND_RETURN;
    }

    HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (!hNtdll) {
        printf("[!] GetModuleHandle failed. Error: %u\n", GetLastError());
        goto CLEANUP_AND_RETURN;
    }

    PNtQueryInformationProcess NtQueryInformationProcess = (PNtQueryInformationProcess) GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        printf("[!] GetProcAddress failed. Error: %u\n", GetLastError());
        goto CLEANUP_AND_RETURN;
    }

    if (NtQueryInformationProcess(hProcess, 0, &sProcessBasicInformation, sizeof(sProcessBasicInformation), &qwReturnLength) == 0) {
        *dwParentProcessId = (DWORD) (ULONG_PTR) sProcessBasicInformation.InheritedFromUniqueProcessId;
        bResult = true;
    }

CLEANUP_AND_RETURN:
    if (hProcess != NULL) CloseHandle(hProcess);

RETURN:
    return bResult;
}

/**
 * Enable all present privileges on the given token.
 * 
 * @param HANDLE hToken The token to enable the present privileges on.
 * @return bool Positive if all privileges have been enabled.
 */
bool EnableAllPrivileges(HANDLE hToken) {
    bool bResult = false;
    DWORD dwSize = 0;
    PTOKEN_PRIVILEGES pPrivileges;

    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    pPrivileges = (PTOKEN_PRIVILEGES) malloc(dwSize);
    if (!pPrivileges) {
        printf("[!] Failed to allocate memory. Error: %u\n", GetLastError());
        goto CLEANUP_AND_RETURN;
    }

    if (!GetTokenInformation(hToken, TokenPrivileges, pPrivileges, dwSize, &dwSize)) {
        printf("[!] Failed to get token information. Error: %u\n", GetLastError());
        goto CLEANUP_AND_RETURN;
    }

    for (DWORD i = 0; i < pPrivileges->PrivilegeCount; i++) {
        pPrivileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
    }

    bResult = AdjustTokenPrivileges(hToken, FALSE, pPrivileges, dwSize, NULL, NULL);
    if (!bResult || GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] Failed to enable all privileges. Error: %u\n", GetLastError());
        goto CLEANUP_AND_RETURN;
    }

CLEANUP_AND_RETURN:
    if (pPrivileges != NULL) free(pPrivileges);

RETURN:
    return bResult;
}

/**
 * Instruct program to enable all present privileges on the parent process.
 *
 * @param int argc Amount of arguments in argv.
 * @param char** Array of arguments passed to the program.
 */
void main(int argc, char** argv) {
    DWORD dwParentProcessId;

    puts("EnableAllPrivilegesOfParentProcess v1.0!\n");

    if (!GetParentProcessId(&dwParentProcessId)) {
        puts("[!] Failed to get parent process ID.");
        goto CLEANUP_PAUSE_AND_RETURN;
    }

    HANDLE hParentProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwParentProcessId);
    if (!hParentProcess) {
        puts("[!] Failed to open parent process.");
        goto CLEANUP_PAUSE_AND_RETURN;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hParentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        puts("[!] Failed to open parent process token.");
        goto CLEANUP_PAUSE_AND_RETURN;
    }

    if (EnableAllPrivileges(hToken)) {
        puts("[+] Successfully enabled all privileges on the parent process.");
    } else {
        puts("[!] Failed to enable all privileges on the parent process.");
    }

CLEANUP_PAUSE_AND_RETURN:
    if (hToken != NULL) CloseHandle(hToken);
    if (hParentProcess != NULL) CloseHandle(hParentProcess);

PAUSE_AND_RETURN:
    puts("[+] Press enter to quit.");
    getchar();
}