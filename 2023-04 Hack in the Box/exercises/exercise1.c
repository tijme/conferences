/*
 *  Exercise 1
 *  Finding and opening a handle to the target driver
 *  Pass the driver name as a command-line argument
 */



#include <stdio.h>
#include <windows.h>

int main(int argc, char *argv[]) {

    char filename[MAX_PATH];
    HANDLE file_handle;


    if (argc != 2) {
        fprintf(stderr, "Usage: %s <driver_path>\n", argv[0]);
        return 1;
    }

    
    /*
     *  Device names like "\Device\x" are object manager internal
     *  names, inaccessible to us. We have to prepend them with
     *  "\\.\" to get access.
     */
    snprintf(filename, MAX_PATH, "\\\\.\\%s", argv[1]);

    file_handle = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (file_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening file: %s\n"
                         "You might have provided the wrong name or the driver isn't running\n", 
                         filename);
        return 1;
    }

    printf("Successfully opened file: %s\n", filename);

    CloseHandle(file_handle);

    return 0;
}