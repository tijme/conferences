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
 * Get the integrity level of the given process.
 * 
 * @param HANDLE hProcess The process to get the integrity level for.
 * @param DWORD* dwIntegrityLevel The result integrity level of the given process.
 * @return bool Positive if obtained succesfully.
 */
bool GetIntegrityLevel(HANDLE hProcess, DWORD* dwIntegrityLevel) {
    bool bResult = false;
    HANDLE hToken = NULL;
    DWORD dwLengthNeeded = 0;
    PTOKEN_MANDATORY_LABEL pTokenMandatoryLabel = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("[!] OpenProcessToken failed. Error: %u\n", GetLastError());
        goto CLEANUP_AND_RETURN;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            printf("[!] GetTokenInformation failed. Error: %u\n", GetLastError());
            goto CLEANUP_AND_RETURN;
        }
    }

    pTokenMandatoryLabel = (PTOKEN_MANDATORY_LABEL) LocalAlloc(LPTR, dwLengthNeeded);
    if (pTokenMandatoryLabel == NULL) {
        printf("[!] LocalAlloc failed. Error: %u\n", GetLastError());
        goto CLEANUP_AND_RETURN;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenMandatoryLabel, dwLengthNeeded, &dwLengthNeeded)) {
        printf("GetTokenInformation failed. Error: %u\n", GetLastError());
        goto CLEANUP_AND_RETURN;
    }

    *dwIntegrityLevel = *GetSidSubAuthority(pTokenMandatoryLabel->Label.Sid, (DWORD) (UCHAR) (*GetSidSubAuthorityCount(pTokenMandatoryLabel->Label.Sid) - 1));
    bResult = true;

CLEANUP_AND_RETURN:
    if (pTokenMandatoryLabel != NULL) LocalFree(pTokenMandatoryLabel);
    if (hToken != NULL) CloseHandle(hToken);

RETURN:
    return bResult;
}

/**
 * Instruct program to display the current integrity level.
 *
 * @param int argc Amount of arguments in argv.
 * @param char** Array of arguments passed to the program.
 */
void main(int argc, char** argv) {
    DWORD dwIntegrityLevel = 0;

    puts("DisplayCurrentIntegrityLevel v1.0!\n");
    puts("[+] Trying to obtain current integrity level.");

    if (!GetIntegrityLevel(GetCurrentProcess(), &dwIntegrityLevel)) {
        puts("[!] Could not retrieve current integrity level.");
        goto PAUSE_AND_RETURN;
    }

    if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
        puts("[+] Current Integrity Level: Low");
    } else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
        puts("[+] Current Integrity Level: Medium");
    } else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
        puts("[+] Current Integrity Level: High");
    } else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
        puts("[+] Current Integrity Level: System");
    } else {
        puts("[+] Current Integrity Level: Unknown");
    }

PAUSE_AND_RETURN:
    puts("[+] Press enter to quit.");
    getchar();
}