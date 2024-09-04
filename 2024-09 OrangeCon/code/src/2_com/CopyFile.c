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
    IShellItem* iSrcShellItem = NULL;
    IShellItem* iDstShellItem = NULL;

    // Initializing COM as a Single-Threaded Apartment (STA)
    hResult = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hResult)) {
        printf("[!] Failed to run CoInitializeEx: 0x%X.\n", hResult);
        goto CLEANUP_AND_RETURN;
    }

    // Create IFileOperation interface instance
    hResult = CoCreateInstance(&CLSID_FileOperation, NULL, CLSCTX_ALL, &IID_IFileOperation, (void**) &iFileOperation);
    if (FAILED(hResult)) {
        printf("[!] Failed to run CoCreateInstance: 0x%X.\n", hResult);
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
    if (iFileOperation != NULL) iFileOperation->lpVtbl->Release(iFileOperation);
    if (iSrcShellItem != NULL) iSrcShellItem->lpVtbl->Release(iSrcShellItem);
    if (iDstShellItem != NULL) iDstShellItem->lpVtbl->Release(iDstShellItem);
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
    puts("COM CopyFile v1.0!\n");

    if (argc != 4) {
        wprintf(L"[!] Usage: %s <source file path> <destination folder> <destination file name>\n", argv[0]);
        return;
    }

    wchar_t* pszSrcPath = ConvertToWideString(argv[1]);
    wchar_t* pszDstFolder = ConvertToWideString(argv[2]);
    wchar_t* pszDstName = ConvertToWideString(argv[3]);

    puts("[+] Trying to copy file using IFileOperation COM interface.");

    if (SUCCEEDED(ComCopyFile(pszSrcPath, pszDstFolder, pszDstName))) {
        printf("[+] Successfully copied %S to %S\\%S.\n", pszSrcPath, pszDstFolder, pszDstName);
    } else {
        printf("[+] Failed to copy %S to %S\\%S.\n", pszSrcPath, pszDstFolder, pszDstName);
    }
}