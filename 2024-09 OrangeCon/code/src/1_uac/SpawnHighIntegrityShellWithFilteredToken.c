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
 * Security Descriptor Definition Language (SDDL)
 * 
 * WIN32 functions, types, and definitions related to Security Descriptor Definition Language.
 * https://learn.microsoft.com/en-us/windows/win32/api/sddl/
 */
#include <sddl.h>

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
 * Instruct program to spawn a high integrity shell with a filtered token.
 *
 * @param int argc Amount of arguments in argv.
 * @param char** Array of arguments passed to the program.
 */
void main(int argc, char** argv) {
    DWORD dwSize;
    HANDLE hCurrentProcess;
    HANDLE hCurrentToken;
    HANDLE hRestrictedToken;
    TOKEN_ELEVATION sTokenElevation;
    STARTUPINFOW sStartupInformation;
    PROCESS_INFORMATION sProcessInformation;

    puts("SpawnHighIntegrityShellWithFilteredToken v1.0!\n");

    hCurrentProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    if (!hCurrentProcess) {
        printf("[!] Failed to open current process: 0x%X.\n", GetLastError());
        goto CLEANUP_PAUSE_AND_RETURN;
    } else {
        puts("[+] Opened handle to current process.");
    }

    if (!OpenProcessToken(hCurrentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &hCurrentToken)) {
        printf("[!] Failed to open current process token: 0x%X.\n", GetLastError());
        goto CLEANUP_PAUSE_AND_RETURN;
    } else {
        puts("[+] Opened handle to token of current process.");
    }

    if (!GetTokenInformation(hCurrentToken, TokenElevation, &sTokenElevation, sizeof(sTokenElevation), &dwSize)) {
        printf("[!] Failed to get current process token information: 0x%X.\n", GetLastError());
        goto CLEANUP_PAUSE_AND_RETURN;
    } else {
        puts("[+] Obtained current process token information.");
    }

    if (!sTokenElevation.TokenIsElevated) {
        puts("[!] Current user is not elevated, a requirement for the creation of the new token.");
        goto CLEANUP_PAUSE_AND_RETURN;
    }

    if (!EnableAllPrivileges(hCurrentToken)) {
        puts("[!] Failed to enable all privileges on the parent process.");
        goto CLEANUP_PAUSE_AND_RETURN;
    } else {
        puts("[+] Successfully enabled all privileges on the parent process.");
    }

    if (!CreateRestrictedToken(hCurrentToken, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &hRestrictedToken)) {
        printf("[!] Could not create restricted token: 0x%X.\n", GetLastError());
        goto CLEANUP_PAUSE_AND_RETURN;
    } else {
        puts("[+] Created restricted token.");
    }

    ZeroMemory(&sProcessInformation, sizeof(sProcessInformation));
    ZeroMemory(&sStartupInformation, sizeof(sStartupInformation));
    sStartupInformation.cb = sizeof(sStartupInformation);

    if (!CreateProcessWithTokenW(hRestrictedToken, 0, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &sStartupInformation, &sProcessInformation)) {
        printf("[!] Could not create process with restricted token: 0x%X.\n", GetLastError());
        goto CLEANUP_PAUSE_AND_RETURN;
    } else {
        puts("[+] Created process withrestricted token.");
    }

    CloseHandle(sProcessInformation.hThread);
    CloseHandle(sProcessInformation.hProcess);
    CloseHandle(hRestrictedToken);
    CloseHandle(hCurrentToken);
    CloseHandle(hCurrentProcess);

CLEANUP_PAUSE_AND_RETURN:
    if (hRestrictedToken != NULL) CloseHandle(hRestrictedToken);
    if (hCurrentToken != NULL) CloseHandle(hCurrentToken);
    if (hCurrentProcess != NULL) CloseHandle(hCurrentProcess);

PAUSE_AND_RETURN:
    puts("[+] Press enter to quit.");
    getchar();
}